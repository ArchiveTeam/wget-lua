#include "wget.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <tmpdir.h>
#include <unistd.h>
#include <xalloc.h>
#include "xmemdup0.h"

#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <nss.h>
#include <nss/ssl.h>
#include <nss/sslexp.h>
#include <nss/sslerr.h>
#include <nss/sslproto.h>
#include <nss/sslt.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>
#include <prio.h>
#include <private/pprio.h>
#include <base64.h>
#include <secerr.h>
#include <secitem.h>
#include <secmod.h>
#ifdef HAVE_BROTLI
# include <brotli/decode.h>
#endif
#ifdef HAVE_LIBZ
# include <zlib.h>
#endif
#ifdef HAVE_ZSTD
# include <zstd.h>
#endif

#include "connect.h"
#include "log.h"
#include "ptimer.h"
#include "ssl.h"
#include "utils.h"

#ifdef WINDOWS
# include <w32sock.h>
#endif

#if defined(WIN32)
static const char *pem_library = "nsspem.dll";
static const char *trust_library = "nssckbi.dll";
#elif defined(__APPLE__)
static const char *pem_library = "libnsspem.dylib";
static const char *trust_library = "libnssckbi.dylib";
#else
static const char *pem_library = "libnsspem.so";
static const char *trust_library = "libnssckbi.so";
#endif

#if defined(SSL_ENABLE_ALPN) \
    && defined(HAVE_LIBZ) \
    && defined(HAVE_ZSTD) \
    && defined(HAVE_BROTLI) \
    && defined(SSL_ENABLE_SESSION_TICKETS) \
    && defined(SSL_ENABLE_TLS13_COMPAT_MODE) \
    && defined(SSL_REQUIRE_SAFE_NEGOTIATION) \
    && defined(SSL_ENABLE_EXTENDED_MASTER_SECRET) \
    && defined(SSL_ENABLE_HELLO_DOWNGRADE_CHECK) \
    && defined(SSL_ENABLE_0RTT_DATA) \
    && defined(SSL_ENABLE_DELEGATED_CREDENTIALS) \
    && defined(SSL_ENABLE_OCSP_STAPLING) \
    && defined(SSL_ENABLE_SIGNED_CERT_TIMESTAMPS) \
    && (NSS_VMAJOR > 3 || (NSS_VMAJOR == 3 && NSS_VMINOR >= 105))
# define NSS_SUPPORTS_FIREFOX_H1 1
#else
# define NSS_SUPPORTS_FIREFOX_H1 0
#endif

struct loaded_object
{
  PK11GenericObject *obj;
  struct loaded_object *next;
};

struct loaded_crl
{
  SECItem *item;
  struct loaded_crl *next;
};

struct nss_transport_context
{
  PRFileDesc *handle;
  PRErrorCode last_error;
  char *cipher_name;
};

static struct
{
  bool ssl_initialized;
  bool nspr_initialized;
  NSSInitContext *context;
  char *temp_cert_db_dir;
  SECMODModule *pem_module;
  SECMODModule *trust_module;
  struct loaded_object *loaded_pem_objects;
  struct loaded_crl *loaded_crls;
  CERTCertificate *client_cert;
  char *client_cert_nickname;
  SECKEYPrivateKey *client_key;
} nss;

static const char *
nss_error_name (PRErrorCode err)
{
  const char *name = PR_ErrorToName (err);
  return name ? name : "unknown error";
}

static void
nss_log_error (enum log_options o, const char *prefix)
{
  PRErrorCode err = PR_GetError ();
  const char *text = PR_ErrorToString (err, PR_LANGUAGE_I_DEFAULT);

  if (text)
    logprintf (o, "%s: %s (%s)\n", prefix, text, nss_error_name (err));
  else
    logprintf (o, "%s: NSS error %d (%s)\n", prefix, err, nss_error_name (err));
}

static PRIntervalTime
timeout_to_interval (double timeout)
{
  if (timeout == -1)
    timeout = opt.read_timeout;

  if (timeout <= 0)
    return PR_INTERVAL_NO_TIMEOUT;

  if (timeout > (double) PR_UINT32_MAX / 1000.0)
    return PR_INTERVAL_NO_TIMEOUT;

  return PR_MillisecondsToInterval ((PRUint32) (timeout * 1000.0));
}

static SECStatus
nss_load_module (SECMODModule **pmod, const char *library, const char *name)
{
  char *config_string;
  SECMODModule *module;

  if (*pmod)
    return SECSuccess;

  config_string = aprintf ("library=%s name=%s", library, name);
  if (!config_string)
    return SECFailure;

  module = SECMOD_LoadUserModule (config_string, NULL, PR_FALSE);
  xfree (config_string);
  if (!module || !module->loaded)
    {
      if (module)
        SECMOD_DestroyModule (module);
      return SECFailure;
    }

  *pmod = module;
  return SECSuccess;
}

static SECStatus
nss_load_pem_object (CK_OBJECT_CLASS obj_class, const char *filename,
                     bool cacert, bool authenticate,
                     PK11GenericObject **loaded_obj)
{
  PK11SlotInfo *slot;
  PK11GenericObject *pem_object = NULL;
  struct loaded_object *entry;
  CK_BBOOL cktrue = CK_TRUE;
  CK_BBOOL ckfalse = CK_FALSE;
  CK_ATTRIBUTE attrs[4] = {
    { CKA_CLASS, &obj_class, sizeof (obj_class) }, /* cert or key object */
    { CKA_TOKEN, &cktrue, sizeof (cktrue) },       /* persist on the token */
    { CKA_LABEL, (unsigned char *) filename, 0 }   /* use the filename as the label */
  };
  int attr_cnt = countof (attrs) - 1;
  struct stat st;

  /* Check for invalid file. */
  if (!filename || stat (filename, &st) != 0 || !S_ISREG (st.st_mode))
    {
      PR_SetError (obj_class == CKO_PRIVATE_KEY ? SEC_ERROR_BAD_KEY
                                                : SEC_ERROR_UNKNOWN_CERT,
                   0);
      return SECFailure;
    }

  /* Two slots are available:
       * `PEM Token #0`: for CA and trust objects
       * `PEM Token #1`: for client cert and key objects */
  slot = PK11_FindSlotByName (cacert ? "PEM Token #0" : "PEM Token #1");
  if (!slot)
    return SECFailure;

  attrs[2].ulValueLen = (CK_ULONG) strlen (filename) + 1;

  if (obj_class == CKO_CERTIFICATE)
    {
      /* Trust CA cert, not the client cert. */
      attrs[attr_cnt].type = CKA_TRUST;
      attrs[attr_cnt].pValue = cacert ? &cktrue : &ckfalse;
      attrs[attr_cnt++].ulValueLen = sizeof (cktrue);
    }

  /* Import the PEM object. */
  pem_object = PK11_CreateGenericObject (slot, attrs, attr_cnt, PR_FALSE);
  if (!pem_object
      || (authenticate && PK11_Authenticate (slot, PR_TRUE, NULL) != SECSuccess))
    {
      if (pem_object)
        {
          PK11_DestroyGenericObject (pem_object);
          pem_object = NULL;
        }
    }

  PK11_FreeSlot (slot);
  if (!pem_object)
    return SECFailure;

  /* Add to array of loaded objects for later cleanup. */
  entry = xnew0 (struct loaded_object);
  entry->obj = pem_object;
  entry->next = nss.loaded_pem_objects;
  nss.loaded_pem_objects = entry;

  if (loaded_obj)
    *loaded_obj = pem_object;

  return SECSuccess;
}

static SECStatus
nss_load_der_certificate (const char *filename,
                          CERTCertificate **loaded_cert)
{
  struct file_memory *file_data;
  SECItem der = { siBuffer, NULL, 0 };
  CERTCertificate *cert;

  file_data = wget_read_file (filename);
  if (!file_data)
    return SECFailure;

  der.data = (unsigned char *) file_data->content;
  der.len = file_data->length;

  /* Create object from DER data. */
  cert = CERT_NewTempCertificate (CERT_GetDefaultCertDB (), &der, NULL,
                                  PR_FALSE, PR_TRUE);
  wget_read_file_free (file_data);
  if (!cert)
    return SECFailure;

  if (!loaded_cert)
    {
      CERT_DestroyCertificate (cert);
      return SECFailure;
    }

  *loaded_cert = cert;
  return SECSuccess;
}

/* A PKCS#8 key is loaded by stripping off the head and tail parts, and
   directly importing the base64-decoded private key data. */
static SECStatus
nss_load_pkcs8_private_key (const char *filename, enum keyfile_type type,
                            SECKEYPrivateKey **loaded_key)
{
  static const char *begin_marker = "-----BEGIN PRIVATE KEY-----";
  static const char *end_marker = "-----END PRIVATE KEY-----";
  struct file_memory *file_data;
  char *begin = NULL;
  char *end = NULL;
  char *pem = NULL;
  SECItem der = { siBuffer, NULL, 0 };
  SECStatus status = SECFailure;
  PK11SlotInfo *slot = NULL;
  SECKEYPrivateKey *key = NULL;

  /* Read the key. */
  file_data = wget_read_file (filename);
  if (!file_data)
    return SECFailure;

  /* Extract or copy the PKCS#8 key. */
  if (type == keyfile_pem)
    {
      begin = strstr (file_data->content, begin_marker);
      if (!begin)
        goto out;
      begin += strlen (begin_marker);
      begin += strspn (begin, "\r\n");

      end = strstr (begin, end_marker);
      if (!end)
        goto out;

      pem = xmemdup0 (begin, end - begin);
      /* Decode base64 data. */
      if (ATOB_ConvertAsciiToItem (&der, pem) != SECSuccess)
        goto out;
    }
  else
    {
      if (!SECITEM_AllocItem (NULL, &der, file_data->length))
        goto out;
      memcpy (der.data, file_data->content, file_data->length);
    }

  /* Get slot for importing key and maybe login. */
  slot = PK11_GetInternalKeySlot ();
  if (!slot
      || (PK11_NeedLogin (slot)
          && PK11_Authenticate (slot, PR_TRUE, NULL) != SECSuccess))
    goto out;

  /* Import the DER private key and check if all went well. */
  status = PK11_ImportDERPrivateKeyInfoAndReturnKey (slot, &der, NULL, NULL,
                                                     PR_FALSE, PR_TRUE,
                                                     KU_ALL, &key, NULL);
  if (key && (status != SECSuccess || !loaded_key))
    SECKEY_DestroyPrivateKey (key);
  else if (key)
    *loaded_key = key;

out:
  if (slot)
    PK11_FreeSlot (slot);
  SECITEM_FreeItem (&der, PR_FALSE);
  xfree (pem);
  wget_read_file_free (file_data);
  return status;
}

/* Hook for NSS to look up the client certificate and private key. */
static SECStatus
nss_hook_select_client_cert (void *arg _GL_UNUSED, PRFileDesc *sock,
                             struct CERTDistNamesStr *ca_names,
                             struct CERTCertificateStr **ret_cert,
                             struct SECKEYPrivateKeyStr **ret_key)
{
  CERTCertificate *cert;
  void *pin_arg;

  /* Get context for the current socket and find the configured cert. */
  pin_arg = SSL_RevealPinArg (sock);
  cert = nss.client_cert
         ? CERT_DupCertificate (nss.client_cert)
         : PK11_FindCertFromNickname (nss.client_cert_nickname, pin_arg);
  if (!cert)
    return SECFailure;

  /* Either use explicitly imported key, or attempt to find it. */
  *ret_key = nss.client_key
             ? SECKEY_CopyPrivateKey (nss.client_key)
             : PK11_FindKeyByAnyCert (cert, pin_arg);

  /* Check for mismatched cert-key pairs. */
  if (*ret_key
      && SECKEY_GetPrivateKeyType (*ret_key)
         != CERT_GetCertKeyType (&cert->subjectPublicKeyInfo))
    {
      SECKEY_DestroyPrivateKey (*ret_key);
      *ret_key = NULL;
    }

  /* Get rid of cert if key was not loaded. */
  if (!*ret_key)
    {
      CERT_DestroyCertificate (cert);
      return SECFailure;
    }

  *ret_cert = cert;
  (void) ca_names;
  return SECSuccess;
}

static SECStatus
nss_hook_auth_cert (void *arg _GL_UNUSED, PRFileDesc *fd,
                    PRBool checksig, PRBool is_server)
{
  if (opt.check_cert != CHECK_CERT_ON)
    return SECSuccess;

  return SSL_AuthCertificate (CERT_GetDefaultCertDB (), fd, checksig,
                              is_server);
}

#if NSS_SUPPORTS_FIREFOX_H1
static SECStatus
nss_zlib_certificate_decode (const SECItem *input, unsigned char *output,
                             size_t output_len, size_t *used_len)
{
  z_stream stream;
  int ret;

  memset (&stream, 0, sizeof (stream));

  if (inflateInit (&stream) != Z_OK)
    {
      PR_SetError (SEC_ERROR_LIBRARY_FAILURE, 0);
      return SECFailure;
    }

  stream.avail_in = input->len;
  stream.next_in = input->data;
  stream.avail_out = output_len;
  stream.next_out = output;

  ret = inflate (&stream, Z_FINISH);
  if (ret != Z_STREAM_END || stream.avail_in != 0)
    {
      inflateEnd (&stream);
      PR_SetError (SEC_ERROR_BAD_DATA, 0);
      return SECFailure;
    }

  *used_len = stream.total_out;
  inflateEnd (&stream);
  return SECSuccess;
}

static SECStatus
nss_brotli_certificate_decode (const SECItem *input, unsigned char *output,
                               size_t output_len, size_t *used_len)
{
  BrotliDecoderResult result;
  size_t uncompressed_size;

  uncompressed_size = output_len;
  result = BrotliDecoderDecompress (input->len, input->data,
                                    &uncompressed_size, output);
  if (result != BROTLI_DECODER_RESULT_SUCCESS)
    {
      PR_SetError (SEC_ERROR_BAD_DATA, 0);
      return SECFailure;
    }

  *used_len = uncompressed_size;
  return SECSuccess;
}

static SECStatus
nss_zstd_certificate_decode (const SECItem *input, unsigned char *output,
                             size_t output_len, size_t *used_len)
{
  size_t result;

  result = ZSTD_decompress (output, output_len, input->data, input->len);
  if (ZSTD_isError (result))
    {
      PR_SetError (SEC_ERROR_BAD_DATA, 0);
      return SECFailure;
    }

  *used_len = result;
  return SECSuccess;
}

static const SSLNamedGroup firefox_h1_named_groups[] = {
  ssl_grp_kem_mlkem768x25519,
  ssl_grp_ec_curve25519,
  ssl_grp_ec_secp256r1,
  ssl_grp_ec_secp384r1,
  ssl_grp_ec_secp521r1,
  ssl_grp_ffdhe_2048,
  ssl_grp_ffdhe_3072
};

static const SSLSignatureScheme firefox_h1_signatures[] = {
  ssl_sig_ecdsa_secp256r1_sha256,
  ssl_sig_ecdsa_secp384r1_sha384,
  ssl_sig_ecdsa_secp521r1_sha512,
  ssl_sig_rsa_pss_sha256,
  ssl_sig_rsa_pss_sha384,
  ssl_sig_rsa_pss_sha512,
  ssl_sig_rsa_pkcs1_sha256,
  ssl_sig_rsa_pkcs1_sha384,
  ssl_sig_rsa_pkcs1_sha512,
  ssl_sig_ecdsa_sha1,
  ssl_sig_rsa_pkcs1_sha1
};

static const PRUint16 firefox_h1_ciphers[] = {
  TLS_AES_128_GCM_SHA256,
  TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_256_GCM_SHA384,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  TLS_RSA_WITH_AES_128_GCM_SHA256,
  TLS_RSA_WITH_AES_256_GCM_SHA384,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_256_CBC_SHA
};

static const unsigned char firefox_h1_alpn[] = "\010http/1.1";

static const SSLCertificateCompressionAlgorithm firefox_h1_compressions[] = {
  { 1, "zlib", NULL, nss_zlib_certificate_decode },
  { 2, "brotli", NULL, nss_brotli_certificate_decode },
  { 3, "zstd", NULL, nss_zstd_certificate_decode }
};

static const struct
{
  PRInt32 option;
  PRBool value;
} firefox_h1_options[] = {
  { SSL_ENABLE_SESSION_TICKETS, PR_TRUE },
  { SSL_ENABLE_TLS13_COMPAT_MODE, PR_TRUE },
  { SSL_REQUIRE_SAFE_NEGOTIATION, PR_FALSE },
  { SSL_ENABLE_EXTENDED_MASTER_SECRET, PR_TRUE },
  { SSL_ENABLE_HELLO_DOWNGRADE_CHECK, PR_TRUE },
  { SSL_ENABLE_0RTT_DATA, PR_TRUE },
  { SSL_ENABLE_DELEGATED_CREDENTIALS, PR_TRUE },
  { SSL_ENABLE_SIGNED_CERT_TIMESTAMPS, PR_TRUE },
  { SSL_ENABLE_OCSP_STAPLING, PR_TRUE }
};

/* The following is for Firefox 148.0 with HTTP/2 and HTTP/3 disabled,
   with a fresh session, and no private browsing. */
static SECStatus
nss_set_firefox_h1_model (PRFileDesc *model)
{
  const PRUint16 *implemented;
  const PRUint16 num_implemented = SSL_GetNumImplementedCiphers ();
  unsigned int i;

  if (SSL_NamedGroupConfig (model, firefox_h1_named_groups,
                            countof (firefox_h1_named_groups)) != SECSuccess
      || SSL_SendAdditionalKeyShares (model, 2) != SECSuccess
      || SSL_OptionSet (model, SSL_ENABLE_ALPN, PR_TRUE) != SECSuccess
      || SSL_SetNextProtoNego (model, firefox_h1_alpn,
                               sizeof (firefox_h1_alpn) - 1) != SECSuccess
      || SSL_SignatureSchemePrefSet (model, firefox_h1_signatures,
                                     countof (firefox_h1_signatures)) != SECSuccess)
    return SECFailure;

  for (i = 0; i < countof (firefox_h1_compressions); i++)
    {
      SSLCertificateCompressionAlgorithm compression = firefox_h1_compressions[i];

      if (SSL_SetCertificateCompressionAlgorithm (model, compression) != SECSuccess)
        return SECFailure;
    }

  implemented = SSL_GetImplementedCiphers ();

  for (i = 0; i < num_implemented; i++)
    if (SSL_CipherPrefSet (model, implemented[i], PR_FALSE) != SECSuccess)
      return SECFailure;

  for (i = 0; i < countof (firefox_h1_ciphers); i++)
    if (SSL_CipherPrefSet (model, firefox_h1_ciphers[i], PR_TRUE) != SECSuccess)
      return SECFailure;

  for (i = 0; i < countof (firefox_h1_options); i++)
    if (SSL_OptionSet (model, firefox_h1_options[i].option,
                       firefox_h1_options[i].value) != SECSuccess)
      return SECFailure;

  return SECSuccess;
}

static SECStatus
nss_set_firefox_h1_handle (PRFileDesc *handle)
{
  if (SSL_EnableTls13GreaseEch (handle, PR_TRUE) != SECSuccess
      || SSL_SetTls13GreaseEchSize (handle, 100) != SECSuccess)
    return SECFailure;

  return SECSuccess;
}
#endif

bool
ssl_init (void)
{
  DIR *ca_dir;
  struct dirent *entry;
  NSSInitParameters initparams;
  char db_template[1024];
  char *db_spec;
  bool have_any_trust = false;
  int ncerts = 0;

  if (nss.ssl_initialized)
    return true;

#if !NSS_SUPPORTS_FIREFOX_H1
  if (opt.tls_impersonate)
    {
      logprintf (LOG_NOTQUIET,
                 _("ERROR: --tls-impersonate=%s is not supported by this NSS build.\n"),
                 opt.tls_impersonate);
      return false;
    }
#endif

  if (!nss.nspr_initialized)
    {
      PR_Init (PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
      nss.nspr_initialized = true;
    }

  memset (&initparams, 0, sizeof (initparams));
  initparams.length = sizeof (initparams);

  /* Create a temporary certificate database. */
  if (!nss.temp_cert_db_dir
      && (path_search (db_template, sizeof (db_template), NULL,
                       "wget-nss", true) == -1
          || !mkdtemp (db_template)))
    {
      logprintf (LOG_NOTQUIET,
                 _("ERROR: Failed to create a temporary NSS certificate database.\n"));
      return false;
    }
  if (!nss.temp_cert_db_dir)
    nss.temp_cert_db_dir = xstrdup (db_template);

  db_spec = aprintf ("sql:%s", nss.temp_cert_db_dir);
  if (!db_spec)
    {
      ssl_cleanup ();
      return false;
    }

  nss.context = NSS_InitContext (db_spec, "", "", "", &initparams,
                                 NSS_INIT_FORCEOPEN | NSS_INIT_NOROOTINIT
                                 | NSS_INIT_OPTIMIZESPACE
                                 | NSS_INIT_PK11RELOAD);
  xfree (db_spec);
  if (!nss.context)
    {
      nss_log_error (LOG_NOTQUIET, "NSS initialization failed");
      ssl_cleanup ();
      return false;
    }

  if (NSS_SetDomesticPolicy () != SECSuccess)
    {
      nss_log_error (LOG_NOTQUIET, "NSS_SetDomesticPolicy failed");
      ssl_cleanup ();
      return false;
    }

  if (!opt.ca_cert && !opt.ca_directory)
    {
      /* When --ca-certificate and --ca-directory are not given, use the
         internal/built-in NSS trust library. */
      if (nss_load_module (&nss.trust_module, trust_library, "trust") == SECSuccess)
        have_any_trust = true;
      else
        logprintf (LOG_NOTQUIET,
                   _("WARNING: Failed to load the NSS trust module %s.\n"),
                   trust_library);
    }

  if (opt.ca_cert || opt.ca_directory || opt.cert_file || opt.private_key
      || opt.crl_file)
    {
      /* Load the PEM module for CA, CRL, and client credential files. */
      if (nss_load_module (&nss.pem_module, pem_library, "PEM") != SECSuccess)
        {
          logprintf (LOG_NOTQUIET,
                     _("ERROR: Failed to load the NSS PEM module %s.\n"),
                     pem_library);
          ssl_cleanup ();
          return false;
        }
    }

  if (opt.ca_directory)
    {
      ca_dir = opendir (opt.ca_directory);
      if (ca_dir == NULL)
        {
          logprintf (LOG_NOTQUIET, _("ERROR: Cannot open directory %s.\n"),
                     opt.ca_directory);
          ssl_cleanup ();
          return false;
        }

      while ((entry = readdir (ca_dir)) != NULL)
        {
          struct stat st;
          char ca_file[1024];

          if (((unsigned) snprintf (ca_file, sizeof (ca_file), "%s/%s",
                                    opt.ca_directory, entry->d_name))
              >= sizeof (ca_file)
              || stat (ca_file, &st) != 0
              || !S_ISREG (st.st_mode))
            continue;

          if (nss_load_pem_object (CKO_CERTIFICATE, ca_file, true, false, NULL)
              != SECSuccess)
            DEBUGP (("WARNING: Failed to open cert %s: (%d).\n",
                     ca_file, PR_GetError ()));
          else
            ncerts++;
        }

      closedir (ca_dir);
      have_any_trust = true;
    }

  if (opt.ca_cert)
    {
      if (nss_load_pem_object (CKO_CERTIFICATE, opt.ca_cert, true, false, NULL)
          != SECSuccess)
        {
          logprintf (LOG_NOTQUIET, _("ERROR: Failed to open cert %s: (%d).\n"),
                     opt.ca_cert, PR_GetError ());
          ssl_cleanup ();
          return false;
        }

      logprintf (LOG_VERBOSE, _("Loaded CA certificate '%s'\n"), opt.ca_cert);
      have_any_trust = true;
      ncerts++;
    }

  if (opt.crl_file)
    {
      static const char crl_begin_marker[] = "-----BEGIN X509 CRL-----";
      static const char crl_end_marker[] = "-----END X509 CRL-----";
      PRFileDesc *infile = NULL;
      PRFileInfo info;
      SECItem filedata = { 0, NULL, 0 };
      bool failed = false;
      bool loaded = false;

      infile = PR_Open (opt.crl_file, PR_RDONLY, 0);
      if (infile
          && PR_GetOpenFileInfo (infile, &info) == PR_SUCCESS
          && SECITEM_AllocItem (NULL, &filedata, info.size + 1)
          && PR_Read (infile, filedata.data, info.size) == info.size)
        {
          char *cursor = (char *) filedata.data;

          filedata.data[info.size] = '\0';
          filedata.len = info.size;

          /* Loop over the CRLs in the file. */
          while ((cursor = strstr (cursor, crl_begin_marker)) != NULL)
            {
              CERTSignedCrl *crl;
              char *begin = cursor + strlen (crl_begin_marker);
              char *end = strstr (begin, crl_end_marker);
              SECItem *crl_der = NULL;
              char *crl_pem = NULL;

              while (*begin == '\r' || *begin == '\n')
                begin++;

              if (!end
                  || (crl_der = SECITEM_AllocItem (NULL, NULL, 0)) == NULL)
                {
                  failed = true;
                  break;
                }

              /* Read and decode the base64 encoded data. */
              crl_pem = xmemdup0 (begin, end - begin);
              if (ATOB_ConvertAsciiToItem (crl_der, crl_pem) != SECSuccess)
                {
                  xfree (crl_pem);
                  SECITEM_FreeItem (crl_der, PR_TRUE);
                  failed = true;
                  break;
                }

              xfree (crl_pem);
              /* Check if the CRL already exists. */
              crl = SEC_FindCrlByDERCert (CERT_GetDefaultCertDB (), crl_der, 0);
              if (crl)
                {
                  SEC_DestroyCrl (crl);
                  SECITEM_FreeItem (crl_der, PR_TRUE);
                }
              /* Cache the CRL. */
              else if (CERT_CacheCRL (CERT_GetDefaultCertDB (), crl_der)
                       != SECSuccess)
                {
                  SECITEM_FreeItem (crl_der, PR_TRUE);
                  failed = true;
                  break;
                }
              else
                {
                  /* Keep track of cached CRLs for cleanup. */
                  struct loaded_crl *entry = xnew0 (struct loaded_crl);
                  entry->item = crl_der;
                  entry->next = nss.loaded_crls;
                  nss.loaded_crls = entry;
                  SSL_ClearSessionCache ();
                }

              loaded = true;
              cursor = end + strlen (crl_end_marker);
            }
        }

      if (infile)
        PR_Close (infile);
      infile = NULL;
      SECITEM_FreeItem (&filedata, PR_FALSE);

      /* CRL file could not be loaded. */
      if (failed || !loaded)
        {
          logprintf (LOG_NOTQUIET, _("ERROR: Failed to load CRL file '%s': (%d)\n"),
                     opt.crl_file, PR_GetError ());
          ssl_cleanup ();
          return false;
        }

      logprintf (LOG_VERBOSE, _("Loaded CRL file '%s'\n"), opt.crl_file);
    }

  DEBUGP (("Certificates loaded: %d\n", ncerts));

  /* Use the private key from the cert file unless otherwise specified. */
  if (opt.cert_file && !opt.private_key)
    {
      opt.private_key = xstrdup (opt.cert_file);
      opt.private_key_type = opt.cert_type;
    }

  /* Use the cert from the private key file unless otherwise specified. */
  if (!opt.cert_file && opt.private_key)
    {
      opt.cert_file = xstrdup (opt.private_key);
      opt.cert_type = opt.private_key_type;
    }

  if (opt.cert_file && opt.private_key)
    {
      const char *basename;

      /* Load certificate file. First attempt as PEM object, then as DER
         certificate. */
      if ((opt.cert_type == keyfile_pem
           && nss_load_pem_object (CKO_CERTIFICATE, opt.cert_file, false,
                                   false, NULL) != SECSuccess)
          || (opt.cert_type == keyfile_asn1
              && nss_load_der_certificate (opt.cert_file, &nss.client_cert)
                 != SECSuccess))
        {
          nss_log_error (LOG_NOTQUIET, "Unable to load client certificate");
          ssl_cleanup ();
          return false;
        }

      /* Load key by first attempting to load PKCS#8 key, and then as PEM object. */
      if ((nss_load_pkcs8_private_key (opt.private_key, opt.private_key_type,
                                       &nss.client_key) != SECSuccess)
          && (opt.private_key_type != keyfile_pem
              || nss_load_pem_object (CKO_PRIVATE_KEY, opt.private_key, false, true,
                                      NULL) != SECSuccess))
        {
          nss_log_error (LOG_NOTQUIET, "Unable to load client private key");
          ssl_cleanup ();
          return false;
        }

      if (opt.cert_type == keyfile_pem)
        {
          /* Set a nickname for the certificate so we can find it easily in the
             NSS hook later on. */
          basename = strrchr (opt.cert_file, '/');
          basename = basename ? basename + 1 : opt.cert_file;
          xfree (nss.client_cert_nickname);
          nss.client_cert_nickname = aprintf ("PEM Token #1:%s", basename);
          if (!nss.client_cert_nickname)
            {
              logprintf (LOG_NOTQUIET,
                         _("ERROR: Failed to allocate client certificate nickname.\n"));
              ssl_cleanup ();
              return false;
            }
        }

    }

  if (!have_any_trust)
    logputs (LOG_NOTQUIET,
             _("WARNING: NSS trust store is empty, certificate verification may fail.\n"));

  nss.ssl_initialized = true;
  return true;
}

void
ssl_cleanup (void)
{
  struct loaded_object *loaded_object = nss.loaded_pem_objects;
  struct loaded_crl *crl = nss.loaded_crls;

  if (!nss.context && !nss.temp_cert_db_dir)
    return;

  if (nss.context)
    SSL_ClearSessionCache ();

  while (loaded_object)
    {
      struct loaded_object *next = loaded_object->next;
      PK11_DestroyGenericObject (loaded_object->obj);
      xfree (loaded_object);
      loaded_object = next;
    }
  nss.loaded_pem_objects = NULL;

  if (nss.client_cert)
    CERT_DestroyCertificate (nss.client_cert);
  nss.client_cert = NULL;
  xfree (nss.client_cert_nickname);
  nss.client_cert_nickname = NULL;
  if (nss.client_key)
    SECKEY_DestroyPrivateKey (nss.client_key);
  nss.client_key = NULL;

  while (crl)
    {
      struct loaded_crl *next = crl->next;
      if (nss.context)
        CERT_UncacheCRL (CERT_GetDefaultCertDB (), crl->item);
      SECITEM_FreeItem (crl->item, PR_TRUE);
      xfree (crl);
      crl = next;
    }
  nss.loaded_crls = NULL;

  if (nss.pem_module)
    {
      SECMOD_UnloadUserModule (nss.pem_module);
      SECMOD_DestroyModule (nss.pem_module);
      nss.pem_module = NULL;
    }

  if (nss.trust_module)
    {
      SECMOD_UnloadUserModule (nss.trust_module);
      SECMOD_DestroyModule (nss.trust_module);
      nss.trust_module = NULL;
    }

  if (nss.context)
    {
      NSS_ShutdownContext (nss.context);
      nss.context = NULL;
    }

  if (nss.temp_cert_db_dir)
    {
      DIR *dir = opendir (nss.temp_cert_db_dir);
      struct dirent *entry;
      bool success = dir != NULL;

      if (dir)
        {
          /* Remove the database files before removing the directory. */
          while ((entry = readdir (dir)) != NULL)
            {
              char *filename;

              if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, ".."))
                continue;

              filename = aprintf ("%s/%s", nss.temp_cert_db_dir, entry->d_name);
              success = filename && unlink (filename) == 0 && success;
              xfree (filename);
            }

          closedir (dir);
        }
      success = rmdir (nss.temp_cert_db_dir) == 0 && success;
      if (!success)
        DEBUGP (("Failed to remove temporary NSS database %s.\n", nss.temp_cert_db_dir));
      xfree (nss.temp_cert_db_dir);
      nss.temp_cert_db_dir = NULL;
    }
  nss.ssl_initialized = false;
}

static int
wnss_read (int fd _GL_UNUSED, char *buf, int bufsize, void *arg, double timeout)
{
  struct nss_transport_context *ctx = arg;
  int ret = PR_Recv (ctx->handle, buf, bufsize, 0,
                     timeout_to_interval (timeout));

  ctx->last_error = ret < 0 ? PR_GetError () : 0;
  return ret;
}

static int
wnss_write (int fd _GL_UNUSED, char *buf, int bufsize, void *arg)
{
  struct nss_transport_context *ctx = arg;
  int ret = PR_Send (ctx->handle, buf, bufsize, 0,
                     PR_INTERVAL_NO_TIMEOUT);

  ctx->last_error = ret < 0 ? PR_GetError () : 0;
  return ret;
}

static int
wnss_poll (int fd, double timeout, int wait_for, void *arg)
{
  struct nss_transport_context *ctx = arg;

  if ((wait_for & WAIT_FOR_READ) && SSL_DataPending (ctx->handle) > 0)
    return 1;

  if (timeout == -1)
    timeout = opt.read_timeout;
  return select_fd (fd, timeout, wait_for);
}

static int
wnss_peek (int fd _GL_UNUSED, char *buf, int bufsize, void *arg, double timeout)
{
  struct nss_transport_context *ctx = arg;
  int ret = PR_Recv (ctx->handle, buf, bufsize, PR_MSG_PEEK,
                     timeout_to_interval (timeout));

  ctx->last_error = ret < 0 ? PR_GetError () : 0;
  return ret;
}

static const char *
wnss_errstr (int fd _GL_UNUSED, void *arg)
{
  struct nss_transport_context *ctx = arg;

  if (!ctx->last_error)
    return NULL;

  return PR_ErrorToString (ctx->last_error, PR_LANGUAGE_I_DEFAULT);
}

static void
wnss_close (int fd _GL_UNUSED, void *arg)
{
  struct nss_transport_context *ctx = arg;

  if (ctx->handle)
    PR_Close (ctx->handle);
  xfree (ctx->cipher_name);
  xfree (ctx);
}

static struct transport_implementation wnss_transport = {
  wnss_read, wnss_write, wnss_poll,
  wnss_peek, wnss_errstr, wnss_close
};

const char *
ssl_get_cipher_name (int fd)
{
  SSLChannelInfo channel = { 0 };
  SSLCipherSuiteInfo suite = { 0 };
  struct nss_transport_context *ctx = fd_transport_context (fd);

  /* `SSL_GetCipherSuiteInfo` generally returns the IANA cipher suite
     name here, except in one case, which is aborted on below. */
  if (SSL_GetChannelInfo (ctx->handle, &channel, sizeof (channel))
         != SECSuccess
      || channel.length != sizeof (channel)
      || !channel.cipherSuite
      || SSL_GetCipherSuiteInfo (channel.cipherSuite, &suite, sizeof (suite))
         != SECSuccess
      || strcmp (suite.cipherSuiteName, "TLS_DHE_DSS_WITH_RC4_128_SHA") == 0)
    abort ();

  xfree (ctx->cipher_name);
  ctx->cipher_name = xstrdup (suite.cipherSuiteName);
  return ctx->cipher_name;
}

enum secure_protocol
ssl_get_protocol (int fd)
{
  SSLChannelInfo channel = { 0 };
  struct nss_transport_context *ctx = fd_transport_context (fd);

  if (SSL_GetChannelInfo (ctx->handle, &channel, sizeof (channel))
         != SECSuccess
      || channel.length != sizeof (channel))
    abort ();

  switch (channel.protocolVersion)
    {
#ifdef SSL_LIBRARY_VERSION_3_0
    case SSL_LIBRARY_VERSION_3_0:
      return secure_protocol_sslv3;
#endif
    case SSL_LIBRARY_VERSION_TLS_1_0:
      return secure_protocol_tlsv1;
#ifdef SSL_LIBRARY_VERSION_TLS_1_1
    case SSL_LIBRARY_VERSION_TLS_1_1:
      return secure_protocol_tlsv1_1;
#endif
#ifdef SSL_LIBRARY_VERSION_TLS_1_2
    case SSL_LIBRARY_VERSION_TLS_1_2:
      return secure_protocol_tlsv1_2;
#endif
#ifdef SSL_LIBRARY_VERSION_TLS_1_3
    case SSL_LIBRARY_VERSION_TLS_1_3:
      return secure_protocol_tlsv1_3;
#endif
    default:
      abort ();
    }
}

bool
ssl_connect_wget (int fd, const char *hostname, int *continue_session)
{
  PRFileDesc *model = NULL;
  PRFileDesc *nspr_socket = NULL;
  PRFileDesc *handle = NULL;
  const PRUint16 *implemented;
  const PRUint16 num_implemented = SSL_GetNumImplementedCiphers ();
  SSLVersionRange supported;
  SSLVersionRange range;
  SSLCipherSuiteInfo suite;
  struct nss_transport_context *ctx = NULL;
  char *sni_hostname = NULL;
  unsigned int i;
  bool any_enabled = false;
  bool suppress_backend_error = false;

  DEBUGP (("Initiating NSS handshake.\n"));

  assert (nss.context != NULL);

  model = PR_NewTCPSocket ();
  if (!model)
    goto error;
  model = SSL_ImportFD (NULL, model);
  if (!model)
    goto error;

  if (SSL_OptionSet (model, SSL_SECURITY, PR_TRUE) != SECSuccess
      || SSL_OptionSet (model, SSL_HANDSHAKE_AS_SERVER, PR_FALSE) != SECSuccess
      || SSL_OptionSet (model, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess
      || SSL_OptionSet (model, SSL_NO_CACHE, PR_FALSE) != SECSuccess)
    goto error;

  if (SSL_VersionRangeGetSupported (ssl_variant_stream, &supported) != SECSuccess
      || SSL_VersionRangeGetDefault (ssl_variant_stream, &range) != SECSuccess)
    goto error;

#if NSS_SUPPORTS_FIREFOX_H1
  if (opt.tls_impersonate
      && nss_set_firefox_h1_model (model) != SECSuccess)
    goto error;
#endif

  switch (opt.secure_protocol)
    {
    case secure_protocol_auto:
    case secure_protocol_pfs:
      break;

    case secure_protocol_sslv2:
      logprintf (LOG_NOTQUIET, _("NSS does not support SSLv2.\n"));
      goto error;

    case secure_protocol_sslv3:
#ifdef SSL_LIBRARY_VERSION_3_0
      range.min = range.max = SSL_LIBRARY_VERSION_3_0;
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your NSS version is too old to support SSLv3.\n"));
      goto error;
#endif

    case secure_protocol_tlsv1:
      range.min = range.max = SSL_LIBRARY_VERSION_TLS_1_0;
      break;

    case secure_protocol_tlsv1_1:
#ifdef SSL_LIBRARY_VERSION_TLS_1_1
      range.min = range.max = SSL_LIBRARY_VERSION_TLS_1_1;
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your NSS version is too old to support TLSv1.1.\n"));
      goto error;
#endif

    case secure_protocol_tlsv1_2:
#ifdef SSL_LIBRARY_VERSION_TLS_1_2
      range.min = range.max = SSL_LIBRARY_VERSION_TLS_1_2;
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your NSS version is too old to support TLSv1.2.\n"));
      goto error;
#endif

    case secure_protocol_tlsv1_3:
#ifdef SSL_LIBRARY_VERSION_TLS_1_3
      range.min = range.max = SSL_LIBRARY_VERSION_TLS_1_3;
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your NSS version is too old to support TLSv1.3\n"));
      goto error;
#endif

    default:
      logprintf (LOG_NOTQUIET, _("NSS: unimplemented 'secure-protocol' option value %d\n"),
                 opt.secure_protocol);
      logprintf (LOG_NOTQUIET, _("Please report this issue to archiveteam@archiveteam.org\n"));
      abort ();
    }

  if (range.min < supported.min)
    range.min = supported.min;
  if (range.max > supported.max)
    range.max = supported.max;
  if (range.min > range.max
      || SSL_VersionRangeSet (model, &range) != SECSuccess)
    goto error;

  if (continue_session)
    {
      logprintf (LOG_NOTQUIET,
                 _("NSS does not support continuing TLS sessions.\n"));
      suppress_backend_error = true;
      goto error;
    }

  if (opt.tls_ciphers_string)
    {
      /* NSS does not directly support a cipher list string like in OpenSSL, or
         a priority string like in GnuTLS. Instead, for NSS the ciphers string is
         defined as a list of cipher strings to use separated by `,`. */
      const char *cipher = opt.tls_ciphers_string;

      implemented = SSL_GetImplementedCiphers ();

      memset (&suite, 0, sizeof (suite));

      /* Set all ciphers to false before setting some of them. */
      for (i = 0; i < num_implemented; i++)
        SSL_CipherPrefSet (model, implemented[i], PR_FALSE);

      while (cipher && *cipher)
        {
          const char *end;
          size_t len;
          bool matched = false;

          while (*cipher && c_isspace (*cipher))
            cipher++;

          if (!*cipher)
            break;

          /* Split on `,` and strip on whitespace. */
          end = strchr (cipher, ',');
          len = end ? (size_t) (end - cipher) : strlen (cipher);
          while (len > 0 && c_isspace (cipher[len - 1]))
            len--;

          /* Find the matching cipher and set to true to use it. */
          for (i = 0; i < num_implemented; i++)
            {
              if (SSL_GetCipherSuiteInfo (implemented[i], &suite, sizeof (suite))
                  != SECSuccess)
                continue;

              if (strlen (suite.cipherSuiteName) == len
                  && !strncasecmp (suite.cipherSuiteName, cipher, len))
                {
                  matched = SSL_CipherPrefSet (model, implemented[i], PR_TRUE)
                            == SECSuccess;
                  break;
                }
            }

          if (!matched)
            {
              logprintf (LOG_NOTQUIET,
                         _("NSS: Invalid cipher suite name: %.*s\n"),
                         (int) len, cipher);
              goto error;
            }

          cipher = end ? end + 1 : NULL;
        }
    }
  else if (opt.secure_protocol == secure_protocol_pfs)
    {
      implemented = SSL_GetImplementedCiphers ();

      memset (&suite, 0, sizeof (suite));

      for (i = 0; i < num_implemented; i++)
        SSL_CipherPrefSet (model, implemented[i], PR_FALSE);

      /* Enable only ciphers that provide forward secrecy, which includes
         all TLS 1.3 and TLS 1.2 ECDHE and DHE ciphers. */
      for (i = 0; i < num_implemented; i++)
        {
          if (SSL_GetCipherSuiteInfo (implemented[i], &suite, sizeof (suite))
              != SECSuccess)
            continue;

          if (((suite.keaType == ssl_kea_tls13_any)
               || (suite.keaTypeName
                   && (!strcmp (suite.keaTypeName, "ECDHE")
                       || !strcmp (suite.keaTypeName, "DHE")))
               || (suite.cipherSuiteName
                   && (strstr (suite.cipherSuiteName, "_ECDHE_") != NULL
                       || strstr (suite.cipherSuiteName, "_DHE_") != NULL)))
              && SSL_CipherPrefSet (model, implemented[i], PR_TRUE) == SECSuccess)
            any_enabled = true;
        }

      if (!any_enabled)
        {
          logprintf (LOG_NOTQUIET, _("NSS: no PFS ciphers are available.\n"));
          goto error;
        }
    }

#ifndef FD_TO_SOCKET
# define FD_TO_SOCKET(X) (X)
#endif
  nspr_socket = PR_ImportTCPSocket (FD_TO_SOCKET (fd));
  if (!nspr_socket)
    goto error;

  handle = SSL_ImportFD (model, nspr_socket);
  if (!handle)
    goto error;
  PR_Close (model);
  model = NULL;
  nspr_socket = NULL;

  if (SSL_AuthCertificateHook (handle, nss_hook_auth_cert, NULL) != SECSuccess)
    goto error;

  if (opt.cert_file
      && SSL_GetClientAuthDataHook (handle, nss_hook_select_client_cert, NULL)
         != SECSuccess)
    goto error;

  sni_hostname = xstrdup (hostname);

  if (SSL_SetURL (handle, sni_hostname) != SECSuccess)
    goto error;

#if NSS_SUPPORTS_FIREFOX_H1
  if (opt.tls_impersonate
      && nss_set_firefox_h1_handle (handle) != SECSuccess)
    goto error;
#endif

  if (SSL_ResetHandshake (handle, PR_FALSE) != SECSuccess)
    goto error;

  if (SSL_ForceHandshakeWithTimeout (handle, timeout_to_interval (opt.read_timeout))
      != SECSuccess)
    goto error;

  ctx = xnew0 (struct nss_transport_context);
  ctx->handle = handle;
  fd_register_transport (fd, &wnss_transport, ctx);

  xfree (sni_hostname);
  return true;

error:
  if (errno == ETIMEDOUT)
    DEBUGP (("NSS handshake timed out.\n"));
  else
    DEBUGP (("NSS handshake failed.\n"));

  if (!suppress_backend_error)
    nss_log_error (LOG_NOTQUIET, "NSS");
  xfree (sni_hostname);
  if (handle)
    PR_Close (handle);
  else if (nspr_socket)
    PR_Close (nspr_socket);
  if (model)
    PR_Close (model);
  xfree (ctx);
  return false;
}

static bool
pkp_pin_peer_pubkey (CERTCertificate *cert, const char *pinnedpubkey)
{
  SECKEYPublicKey *pubkey;
  SECItem *pubkey_der;
  bool success;

  if (!pinnedpubkey)
    return true;

  if (!cert)
    return false;

  pubkey = CERT_ExtractPublicKey (cert);
  if (!pubkey)
    return false;

  /* Create DER encoded version of public key. */
  pubkey_der = PK11_DEREncodePublicKey (pubkey);
  SECKEY_DestroyPublicKey (pubkey);
  if (!pubkey_der)
    return false;

  /* Check for a match with the pinned public key. */
  success = wg_pin_peer_pubkey (pinnedpubkey, (const char *) pubkey_der->data,
                                pubkey_der->len);
  SECITEM_FreeItem (pubkey_der, PR_TRUE);
  return success;
}

bool
ssl_check_certificate (int fd, const char *host)
{
  struct nss_transport_context *ctx = fd_transport_context (fd);
  CERTCertificate *cert = NULL;
  PRTime not_before;
  PRTime not_after;
  PRTime now = PR_Now ();
  const char *severity = opt.check_cert ? _("ERROR") : _("WARNING");
  bool success = true;
  bool pinsuccess = opt.pinnedpubkey == NULL;

  /* If the user has specified --no-check-cert, we still want to warn
     him about problems with the server's certificate.  */
  if (opt.check_cert == CHECK_CERT_QUIET && pinsuccess)
    return success;

  cert = SSL_PeerCertificate (ctx->handle);
  if (!cert)
    {
      logprintf (LOG_NOTQUIET, _("%s: No certificate presented by %s.\n"),
                 severity, quotearg_style (escape_quoting_style, host));
      success = false;
      goto out;
    }

  if (opt.check_cert != CHECK_CERT_ON
      && CERT_VerifyCertNow (CERT_GetDefaultCertDB (), cert, PR_TRUE,
                             certUsageSSLServer, NULL) != SECSuccess)
    {
      PRErrorCode err = PR_GetError ();
      const char *errstr = PR_ErrorToString (err, PR_LANGUAGE_I_DEFAULT);

      switch (err)
        {
        case SEC_ERROR_UNKNOWN_ISSUER:
          logprintf (LOG_NOTQUIET,
                     _("%s: The certificate of %s doesn't have a known issuer.\n"),
                     severity, quote (host));
          break;
        case SEC_ERROR_REVOKED_CERTIFICATE:
          logprintf (LOG_NOTQUIET,
                     _("%s: The certificate of %s has been revoked.\n"),
                     severity, quote (host));
          break;
        case SEC_ERROR_UNTRUSTED_ISSUER:
        case SEC_ERROR_UNTRUSTED_CERT:
        case SEC_ERROR_CA_CERT_INVALID:
          logprintf (LOG_NOTQUIET,
                     _("%s: The certificate of %s is not trusted.\n"),
                     severity, quote (host));
          break;
        case SEC_ERROR_EXPIRED_CERTIFICATE:
          logprintf (LOG_NOTQUIET,
                     _("%s: The certificate of %s has expired.\n"),
                     severity, quote (host));
          break;
        case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
          logprintf (LOG_NOTQUIET,
                     _("%s: The issuer certificate of %s has expired.\n"),
                     severity, quote (host));
          break;
        case SEC_ERROR_CERT_NOT_VALID:
          logprintf (LOG_NOTQUIET,
                     _("%s: The certificate of %s is not yet activated.\n"),
                     severity, quote (host));
          break;
        default:
          logprintf (LOG_NOTQUIET,
                     _("%s: Cannot verify %s's certificate: %s\n"),
                     severity, quote (host),
                     errstr ? errstr : nss_error_name (err));
          break;
        }
      success = false;
    }

  /* NSS peer certificates are always X.509 certificates. */
  if (CERT_GetCertTimes (cert, &not_before, &not_after) == SECSuccess)
    {
      if (now < not_before)
        {
          logprintf (LOG_NOTQUIET,
                     _("The certificate has not yet been activated\n"));
          success = false;
        }
      if (now >= not_after)
        {
          logprintf (LOG_NOTQUIET, _("The certificate has expired\n"));
          success = false;
        }
    }

  if (! is_valid_ip_address (host))
    {
      size_t len = strlen (host);
      char *verify_hostname = xstrdup (host);

      /* Strip off trailing `.` for hostname verification. */
      while (len && verify_hostname[--len] == '.')
        verify_hostname[len] = '\0';

      if (CERT_VerifyCertName (cert, verify_hostname) != SECSuccess)
        {
          logprintf (LOG_NOTQUIET,
                     _("The certificate's owner does not match hostname %s\n"),
                     quote (verify_hostname));
          success = false;
        }
      xfree (verify_hostname);
    }

  pinsuccess = pkp_pin_peer_pubkey (cert, opt.pinnedpubkey);
  if (!pinsuccess)
    {
      logprintf (LOG_ALWAYS, _("The public key does not match pinned public key!\n"));
      success = false;
    }

  if (success)
    DEBUGP (("X509 certificate successfully verified and matches host %s\n",
             quotearg_style (escape_quoting_style, host)));

out:
  if (cert)
    CERT_DestroyCertificate (cert);

  return !pinsuccess ? false : (opt.check_cert == CHECK_CERT_ON ? success : true);
}
