export VC_LIST_EXCEPT_DEFAULT=^(lib/.*|m4/.*|md5/.*|build-aux/.*|src/gettext\.h|.*ChangeLog)$$

local-checks-to-skip = \
    sc_const_long_option \
    sc_error_message_uppercase \
    sc_file_system \
    sc_immutable_NEWS \
    sc_copyright_check \
    sc_makefile_path_separator_check \
    sc_require_config_h \
    sc_require_config_h_first \
    sc_two_space_separator_in_usage \
    sc_useless_cpp_parens \
    \
    sc_prohibit_atoi_atof \
    sc_prohibit_strcmp \
    sc_cast_of_alloca_return_value \
    sc_cast_of_x_alloc_return_value \
    sc_prohibit_S_IS_definition \
    \
    sc_program_name \
    sc_makefile_at_at_check \
    sc_cast_of_argument_to_free \

#SHELL=bash -x
show-vc-list-except:
	@$(VC_LIST_EXCEPT)

VC_LIST_ALWAYS_EXCLUDE_REGEX = ^ABOUT-NLS|((msdos|vms)/.*)|ChangeLog-2014-12-10$$
