/** @file zopt.h
 *  @brief The header file for the command line option parser
 *  generated by GNU Gengetopt version 2.22.5
 *  http://www.gnu.org/software/gengetopt.
 *  DO NOT modify this file, since it can be overwritten
 *  @author GNU Gengetopt by Lorenzo Bettini */

#ifndef ZOPT_H
#define ZOPT_H

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h> /* for FILE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMDLINE_PARSER_PACKAGE
/** @brief the program name (used for printing errors) */
#define CMDLINE_PARSER_PACKAGE "zmap"
#endif

#ifndef CMDLINE_PARSER_PACKAGE_NAME
/** @brief the complete program name (used for help and version) */
#define CMDLINE_PARSER_PACKAGE_NAME "zmap"
#endif

#ifndef CMDLINE_PARSER_VERSION
/** @brief the program version */
#define CMDLINE_PARSER_VERSION "1.2.0-RC3"
#endif

/** @brief Where the command line options are stored */
struct gengetopt_args_info
{
  int target_port_arg;	/**< @brief TCP port number to scan (for SYN scans).  */
  char * target_port_orig;	/**< @brief TCP port number to scan (for SYN scans) original value given at command line.  */
  const char *target_port_help; /**< @brief TCP port number to scan (for SYN scans) help description.  */
  char * output_file_arg;	/**< @brief Output file.  */
  char * output_file_orig;	/**< @brief Output file original value given at command line.  */
  const char *output_file_help; /**< @brief Output file help description.  */
  char * blacklist_file_arg;	/**< @brief File of subnets to exclude, in CIDR notation, e.g. 192.168.0.0/16.  */
  char * blacklist_file_orig;	/**< @brief File of subnets to exclude, in CIDR notation, e.g. 192.168.0.0/16 original value given at command line.  */
  const char *blacklist_file_help; /**< @brief File of subnets to exclude, in CIDR notation, e.g. 192.168.0.0/16 help description.  */
  char * whitelist_file_arg;	/**< @brief File of subnets to constrain scan to, in CIDR notation, e.g. 192.168.0.0/16.  */
  char * whitelist_file_orig;	/**< @brief File of subnets to constrain scan to, in CIDR notation, e.g. 192.168.0.0/16 original value given at command line.  */
  const char *whitelist_file_help; /**< @brief File of subnets to constrain scan to, in CIDR notation, e.g. 192.168.0.0/16 help description.  */
  char * output_fields_arg;	/**< @brief Fields that should be output in result set.  */
  char * output_fields_orig;	/**< @brief Fields that should be output in result set original value given at command line.  */
  const char *output_fields_help; /**< @brief Fields that should be output in result set help description.  */
  char * max_targets_arg;	/**< @brief Cap number of targets to probe (as a number or a percentage of the address space).  */
  char * max_targets_orig;	/**< @brief Cap number of targets to probe (as a number or a percentage of the address space) original value given at command line.  */
  const char *max_targets_help; /**< @brief Cap number of targets to probe (as a number or a percentage of the address space) help description.  */
  int max_results_arg;	/**< @brief Cap number of results to return.  */
  char * max_results_orig;	/**< @brief Cap number of results to return original value given at command line.  */
  const char *max_results_help; /**< @brief Cap number of results to return help description.  */
  int max_runtime_arg;	/**< @brief Cap length of time for sending packets.  */
  char * max_runtime_orig;	/**< @brief Cap length of time for sending packets original value given at command line.  */
  const char *max_runtime_help; /**< @brief Cap length of time for sending packets help description.  */
  int rate_arg;	/**< @brief Set send rate in packets/sec.  */
  char * rate_orig;	/**< @brief Set send rate in packets/sec original value given at command line.  */
  const char *rate_help; /**< @brief Set send rate in packets/sec help description.  */
  char * bandwidth_arg;	/**< @brief Set send rate in bits/second (supports suffixes G, M and K).  */
  char * bandwidth_orig;	/**< @brief Set send rate in bits/second (supports suffixes G, M and K) original value given at command line.  */
  const char *bandwidth_help; /**< @brief Set send rate in bits/second (supports suffixes G, M and K) help description.  */
  int cooldown_time_arg;	/**< @brief How long to continue receiving after sending last probe (default='8').  */
  char * cooldown_time_orig;	/**< @brief How long to continue receiving after sending last probe original value given at command line.  */
  const char *cooldown_time_help; /**< @brief How long to continue receiving after sending last probe help description.  */
  int seed_arg;	/**< @brief Seed used to select address permutation.  */
  char * seed_orig;	/**< @brief Seed used to select address permutation original value given at command line.  */
  const char *seed_help; /**< @brief Seed used to select address permutation help description.  */
  int sender_threads_arg;	/**< @brief Threads used to send packets (default='1').  */
  char * sender_threads_orig;	/**< @brief Threads used to send packets original value given at command line.  */
  const char *sender_threads_help; /**< @brief Threads used to send packets help description.  */
  int probes_arg;	/**< @brief Number of probes to send to each IP (default='1').  */
  char * probes_orig;	/**< @brief Number of probes to send to each IP original value given at command line.  */
  const char *probes_help; /**< @brief Number of probes to send to each IP help description.  */
  const char *dryrun_help; /**< @brief Don't actually send packets help description.  */
  int shards_arg;	/**< @brief Set the total number of shards (default='1').  */
  char * shards_orig;	/**< @brief Set the total number of shards original value given at command line.  */
  const char *shards_help; /**< @brief Set the total number of shards help description.  */
  int shard_arg;	/**< @brief Set which shard this scan is (0 indexed) (default='0').  */
  char * shard_orig;	/**< @brief Set which shard this scan is (0 indexed) original value given at command line.  */
  const char *shard_help; /**< @brief Set which shard this scan is (0 indexed) help description.  */
  char * source_port_arg;	/**< @brief Source port(s) for scan packets.  */
  char * source_port_orig;	/**< @brief Source port(s) for scan packets original value given at command line.  */
  const char *source_port_help; /**< @brief Source port(s) for scan packets help description.  */
  char * source_ip_arg;	/**< @brief Source address(es) for scan packets.  */
  char * source_ip_orig;	/**< @brief Source address(es) for scan packets original value given at command line.  */
  const char *source_ip_help; /**< @brief Source address(es) for scan packets help description.  */
  char * gateway_mac_arg;	/**< @brief Specify gateway MAC address.  */
  char * gateway_mac_orig;	/**< @brief Specify gateway MAC address original value given at command line.  */
  const char *gateway_mac_help; /**< @brief Specify gateway MAC address help description.  */
  char * interface_arg;	/**< @brief Specify network interface to use.  */
  char * interface_orig;	/**< @brief Specify network interface to use original value given at command line.  */
  const char *interface_help; /**< @brief Specify network interface to use help description.  */
  const char *vpn_help; /**< @brief Sends IP packets instead of Ethernet (for VPNs) help description.  */
  char * probe_module_arg;	/**< @brief Select probe module (default='tcp_synscan').  */
  char * probe_module_orig;	/**< @brief Select probe module original value given at command line.  */
  const char *probe_module_help; /**< @brief Select probe module help description.  */
  char * output_module_arg;	/**< @brief Select output module (default='default').  */
  char * output_module_orig;	/**< @brief Select output module original value given at command line.  */
  const char *output_module_help; /**< @brief Select output module help description.  */
  char * probe_args_arg;	/**< @brief Arguments to pass to probe module.  */
  char * probe_args_orig;	/**< @brief Arguments to pass to probe module original value given at command line.  */
  const char *probe_args_help; /**< @brief Arguments to pass to probe module help description.  */
  char * output_args_arg;	/**< @brief Arguments to pass to output module.  */
  char * output_args_orig;	/**< @brief Arguments to pass to output module original value given at command line.  */
  const char *output_args_help; /**< @brief Arguments to pass to output module help description.  */
  char * output_filter_arg;	/**< @brief Specify a filter over the response fields to limit what responses get sent to the output module.  */
  char * output_filter_orig;	/**< @brief Specify a filter over the response fields to limit what responses get sent to the output module original value given at command line.  */
  const char *output_filter_help; /**< @brief Specify a filter over the response fields to limit what responses get sent to the output module help description.  */
  const char *list_output_modules_help; /**< @brief List available output modules help description.  */
  const char *list_probe_modules_help; /**< @brief List available probe modules help description.  */
  const char *list_output_fields_help; /**< @brief List all fields that can be output by selected probe module help description.  */
  char * config_arg;	/**< @brief Read a configuration file, which can specify any of these options (default='/etc/zmap/zmap.conf').  */
  char * config_orig;	/**< @brief Read a configuration file, which can specify any of these options original value given at command line.  */
  const char *config_help; /**< @brief Read a configuration file, which can specify any of these options help description.  */
  char * log_file_arg;	/**< @brief Write log entries to file.  */
  char * log_file_orig;	/**< @brief Write log entries to file original value given at command line.  */
  const char *log_file_help; /**< @brief Write log entries to file help description.  */
  char * log_directory_arg;	/**< @brief Write log entries to a timestamped file in this directory.  */
  char * log_directory_orig;	/**< @brief Write log entries to a timestamped file in this directory original value given at command line.  */
  const char *log_directory_help; /**< @brief Write log entries to a timestamped file in this directory help description.  */
  const char *quiet_help; /**< @brief Do not print status updates help description.  */
  const char *summary_help; /**< @brief Print configuration and summary at end of scan help description.  */
  char * fingerprint_file_arg;	/**< @brief Output file for operating system finger print.  */
  char * fingerprint_file_orig;	/**< @brief Output file for operating system finger print original value given at command line.  */
  const char *fingerprint_file_help; /**< @brief Output file for operating system finger print help description.  */
  char * metadata_file_arg;	/**< @brief Output file for scan metadata (JSON).  */
  char * metadata_file_orig;	/**< @brief Output file for scan metadata (JSON) original value given at command line.  */
  const char *metadata_file_help; /**< @brief Output file for scan metadata (JSON) help description.  */
  const char *disable_syslog_help; /**< @brief Disables logging messages to syslog help description.  */
  int verbosity_arg;	/**< @brief Level of log detail (0-5) (default='3').  */
  char * verbosity_orig;	/**< @brief Level of log detail (0-5) original value given at command line.  */
  const char *verbosity_help; /**< @brief Level of log detail (0-5) help description.  */
  const char *help_help; /**< @brief Print help and exit help description.  */
  const char *version_help; /**< @brief Print version and exit help description.  */
  
  unsigned int target_port_given ;	/**< @brief Whether target-port was given.  */
  unsigned int output_file_given ;	/**< @brief Whether output-file was given.  */
  unsigned int blacklist_file_given ;	/**< @brief Whether blacklist-file was given.  */
  unsigned int whitelist_file_given ;	/**< @brief Whether whitelist-file was given.  */
  unsigned int output_fields_given ;	/**< @brief Whether output-fields was given.  */
  unsigned int max_targets_given ;	/**< @brief Whether max-targets was given.  */
  unsigned int max_results_given ;	/**< @brief Whether max-results was given.  */
  unsigned int max_runtime_given ;	/**< @brief Whether max-runtime was given.  */
  unsigned int rate_given ;	/**< @brief Whether rate was given.  */
  unsigned int bandwidth_given ;	/**< @brief Whether bandwidth was given.  */
  unsigned int cooldown_time_given ;	/**< @brief Whether cooldown-time was given.  */
  unsigned int seed_given ;	/**< @brief Whether seed was given.  */
  unsigned int sender_threads_given ;	/**< @brief Whether sender-threads was given.  */
  unsigned int probes_given ;	/**< @brief Whether probes was given.  */
  unsigned int dryrun_given ;	/**< @brief Whether dryrun was given.  */
  unsigned int shards_given ;	/**< @brief Whether shards was given.  */
  unsigned int shard_given ;	/**< @brief Whether shard was given.  */
  unsigned int source_port_given ;	/**< @brief Whether source-port was given.  */
  unsigned int source_ip_given ;	/**< @brief Whether source-ip was given.  */
  unsigned int gateway_mac_given ;	/**< @brief Whether gateway-mac was given.  */
  unsigned int interface_given ;	/**< @brief Whether interface was given.  */
  unsigned int vpn_given ;	/**< @brief Whether vpn was given.  */
  unsigned int probe_module_given ;	/**< @brief Whether probe-module was given.  */
  unsigned int output_module_given ;	/**< @brief Whether output-module was given.  */
  unsigned int probe_args_given ;	/**< @brief Whether probe-args was given.  */
  unsigned int output_args_given ;	/**< @brief Whether output-args was given.  */
  unsigned int output_filter_given ;	/**< @brief Whether output-filter was given.  */
  unsigned int list_output_modules_given ;	/**< @brief Whether list-output-modules was given.  */
  unsigned int list_probe_modules_given ;	/**< @brief Whether list-probe-modules was given.  */
  unsigned int list_output_fields_given ;	/**< @brief Whether list-output-fields was given.  */
  unsigned int config_given ;	/**< @brief Whether config was given.  */
  unsigned int log_file_given ;	/**< @brief Whether log-file was given.  */
  unsigned int log_directory_given ;	/**< @brief Whether log-directory was given.  */
  unsigned int quiet_given ;	/**< @brief Whether quiet was given.  */
  unsigned int summary_given ;	/**< @brief Whether summary was given.  */
  unsigned int fingerprint_file_given ;	/**< @brief Whether fingerprint-file was given.  */
  unsigned int metadata_file_given ;	/**< @brief Whether metadata-file was given.  */
  unsigned int disable_syslog_given ;	/**< @brief Whether disable-syslog was given.  */
  unsigned int verbosity_given ;	/**< @brief Whether verbosity was given.  */
  unsigned int help_given ;	/**< @brief Whether help was given.  */
  unsigned int version_given ;	/**< @brief Whether version was given.  */

  char **inputs ; /**< @brief unamed options (options without names) */
  unsigned inputs_num ; /**< @brief unamed options number */
} ;

/** @brief The additional parameters to pass to parser functions */
struct cmdline_parser_params
{
  int override; /**< @brief whether to override possibly already present options (default 0) */
  int initialize; /**< @brief whether to initialize the option structure gengetopt_args_info (default 1) */
  int check_required; /**< @brief whether to check that all required options were provided (default 1) */
  int check_ambiguity; /**< @brief whether to check for options already specified in the option structure gengetopt_args_info (default 0) */
  int print_errors; /**< @brief whether getopt_long should print an error message for a bad option (default 1) */
} ;

/** @brief the purpose string of the program */
extern const char *gengetopt_args_info_purpose;
/** @brief the usage string of the program */
extern const char *gengetopt_args_info_usage;
/** @brief all the lines making the help output */
extern const char *gengetopt_args_info_help[];

/**
 * The command line parser
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser (int argc, char **argv,
  struct gengetopt_args_info *args_info);

/**
 * The command line parser (version with additional parameters - deprecated)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_ext() instead
 */
int cmdline_parser2 (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The command line parser (version with additional parameters)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_ext (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Save the contents of the option struct into an already open FILE stream.
 * @param outfile the stream where to dump options
 * @param args_info the option struct to dump
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_dump(FILE *outfile,
  struct gengetopt_args_info *args_info);

/**
 * Save the contents of the option struct into a (text) file.
 * This file can be read by the config file parser (if generated by gengetopt)
 * @param filename the file where to save
 * @param args_info the option struct to save
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_file_save(const char *filename,
  struct gengetopt_args_info *args_info);

/**
 * Print the help
 */
void cmdline_parser_print_help(void);
/**
 * Print the version
 */
void cmdline_parser_print_version(void);

/**
 * Initializes all the fields a cmdline_parser_params structure 
 * to their default values
 * @param params the structure to initialize
 */
void cmdline_parser_params_init(struct cmdline_parser_params *params);

/**
 * Allocates dynamically a cmdline_parser_params structure and initializes
 * all its fields to their default values
 * @return the created and initialized cmdline_parser_params structure
 */
struct cmdline_parser_params *cmdline_parser_params_create(void);

/**
 * Initializes the passed gengetopt_args_info structure's fields
 * (also set default values for options that have a default)
 * @param args_info the structure to initialize
 */
void cmdline_parser_init (struct gengetopt_args_info *args_info);
/**
 * Deallocates the string fields of the gengetopt_args_info structure
 * (but does not deallocate the structure itself)
 * @param args_info the structure to deallocate
 */
void cmdline_parser_free (struct gengetopt_args_info *args_info);

/**
 * The config file parser (deprecated version)
 * @param filename the name of the config file
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_config_file() instead
 */
int cmdline_parser_configfile (const char *filename,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The config file parser
 * @param filename the name of the config file
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_config_file (const char *filename,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Checks that all the required options were specified
 * @param args_info the structure to check
 * @param prog_name the name of the program that will be used to print
 *   possible errors
 * @return
 */
int cmdline_parser_required (struct gengetopt_args_info *args_info,
  const char *prog_name);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* ZOPT_H */
