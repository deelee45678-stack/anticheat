#define _GNU_SOURCE

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debugger.h"
#include "ebpf_monitor.h"
#include "envguard.h"
#include "network.h"
#include "integrity.h"
#include "memguard.h"
#include "report.h"
#include "scanner.h"
#include "telemetry.h"

static volatile sig_atomic_t g_quit = 0;

static void on_signal(int sig) {
    (void)sig;
    g_quit = 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Anti-cheat scanner: process, environment, debugger and file-integrity checks.\n"
            "\n"
            "Scan modes:\n"
            "  (default)                 run process, environment and debugger checks\n"
            "  -m, --manifest FILE       also verify file integrity against baseline FILE\n"
            "\n"
            "Manifest management:\n"
            "  -i, --init FILE           build a baseline manifest from --paths and exit\n"
            "  -v, --verify FILE         verify files against a baseline manifest and exit\n"
            "  -p, --paths a,b,c         comma-separated files to record in the manifest\n"
            "\n"
            "Memory integrity monitor:\n"
            "  -w, --watch               continuously hash own code (.text) region in a\n"
            "                            background thread to detect live patching\n"
            "  -W, --watch-interval MS   monitor check interval in ms (default: 250)\n"
            "  -t, --watch-time SEC      stop after SEC seconds (default: run until signal)\n"
            "  -s, --selftest            simulate an in-process code patch to verify the\n"
            "                            monitor detects it (implies --watch)\n"
            "\n"
            "Server-side telemetry simulation:\n"
            "  -T, --telemetry-sim       simulate player telemetry and run the speedhack\n"
            "                            and aimbot heuristics against an anomaly dataset\n"
            "\n"
            "Kernel-level monitor:\n"
            "  -E, --ebpf                load the eBPF cross-process memory monitor\n"
            "                            (requires root + libbpf; falls back to user\n"
            "                            mode protections otherwise)\n"
            "\n"
            "Other:\n"
            "  -l, --log FILE            append findings to a log file\n"
            "  -q, --quiet               only print findings, no banner/summary\n"
            "  -h, --help                show this help and exit\n"
            "\n"
            "Exit status: 0 = clean, 1 = at least one MEDIUM-or-higher finding.\n",
            prog);
}

static char **split_paths(const char *arg, int *count) {
    char *copy = strdup(arg);
    if (!copy) {
        return NULL;
    }

    size_t n = 1;
    for (const char *p = copy; *p; p++) {
        if (*p == ',') {
            n++;
        }
    }

    char **arr = calloc(n + 1, sizeof(char *));
    if (!arr) {
        free(copy);
        return NULL;
    }

    size_t i = 0;
    char *tok = strtok(copy, ",");
    while (tok) {
        arr[i++] = tok;
        tok = strtok(NULL, ",");
    }
    arr[i] = NULL;

    if (count) {
        *count = (int)i;
    }
    return arr;
}

int main(int argc, char **argv) {
    static const struct option longopts[] = {
        {"init",           required_argument, 0, 'i'},
        {"verify",         required_argument, 0, 'v'},
        {"manifest",       required_argument, 0, 'm'},
        {"paths",          required_argument, 0, 'p'},
        {"log",            required_argument, 0, 'l'},
        {"quiet",          no_argument,       0, 'q'},
        {"help",           no_argument,       0, 'h'},
        {"watch",          no_argument,       0, 'w'},
        {"watch-interval", required_argument, 0, 'W'},
        {"watch-time",     required_argument, 0, 't'},
        {"selftest",       no_argument,       0, 's'},
        {"telemetry-sim",  no_argument,       0, 'T'},
        {"ebpf",           no_argument,       0, 'E'},
        {"network",        required_argument, 0, 'N'},
        {0, 0, 0, 0}
    };

    const char *init_path = NULL;
    const char *verify_path = NULL;
    const char *manifest_path = NULL;
    const char *paths_arg = NULL;
    const char *log_path = NULL;
    int quiet = 0;
    int watch = 0;
    int selftest = 0;
    int telemetry_sim = 0;
    int ebpf_mon = 0;
    const char *network_arg = NULL;
    int watch_interval = 250;
    int watch_time = 0;

    int c;
 while ((c = getopt_long(argc, argv, "i:v:m:p:l:qhwW:t:sTEN:",
                              longopts, NULL)) != -1) {
        switch (c) {
            case 'i':
                init_path = optarg;
                break;
            case 'v':
                verify_path = optarg;
                break;
            case 'm':
                manifest_path = optarg;
                break;
            case 'p':
                paths_arg = optarg;
                break;
            case 'l':
                log_path = optarg;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            case 'w':
                watch = 1;
                break;
            case 's':
                selftest = 1;
                break;
            case 'T':
                telemetry_sim = 1;
                break;
            case 'E':
                ebpf_mon = 1;
                break;
            case 'N':
                network_arg = optarg;
                break;
            case 'W':
                watch_interval = atoi(optarg);
                if (watch_interval < 50) {
                    watch_interval = 50;
                }
                break;
            case 't':
                watch_time = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                return 2;
        }
    }

    reporter_t rep;
    report_init(&rep, log_path);
    report_set_quiet(quiet);

    if (init_path) {
        if (!paths_arg) {
            fprintf(stderr, "error: --init requires --paths\n");
            usage(argv[0]);
            return 2;
        }
        int npaths = 0;
        char **paths = split_paths(paths_arg, &npaths);
        if (!paths || npaths == 0) {
            fprintf(stderr, "error: could not parse --paths\n");
            free(paths);
            return 2;
        }
        int failed = integrity_build_manifest(&rep, init_path,
                                              (const char **)paths);
        free(paths);
        if (failed) {
            return 1;
        }
        if (!quiet) {
            printf("\nBaseline manifest written to %s\n", init_path);
        }
        return 0;
    }

    if (verify_path) {
        int tampered = integrity_verify_manifest(&rep, verify_path);
        report_summary(&rep);
        return tampered;
    }

    if (!quiet) {
        printf("Anti-Cheat Scanner v1.0\n");
        printf("=======================\n");
        printf("self pid: %d\n", getpid());
    }

    /* Initialize the UDP alert client before any findings are recorded so that
     * MEDIUM+ detections are streamed to the dashboard. */
    if (network_arg) {
        char host[256];
        int port = 9999;
        snprintf(host, sizeof(host), "%s", network_arg);
        char *colon = strrchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = atoi(colon + 1);
        }
        if (initialize_network_client(host, port) == 0) {
            report_add(&rep, SEV_INFO, "network",
                       "UDP alert reporting enabled", network_arg);
        } else {
            fprintf(stderr, "warning: could not initialize network client %s\n",
                    network_arg);
        }
    }

    scan_environment(&rep);
    scan_processes(&rep);

    int debugged = is_debugged();
    if (debugged) {
        report_add(&rep, SEV_CRITICAL, "debugger",
                   "this process is being traced or debugged", NULL);
    } else {
        report_add(&rep, SEV_INFO, "debugger",
                   "no debugger attached to this process", NULL);
    }

    int env = envguard_scan(&rep);
    if (env & ENVGUARD_VM) {
        if (debugged) {
            report_add(&rep, SEV_HIGH, "envguard",
                       "virtualized environment confirmed with an attached "
                       "debugger (reverse-engineering sandbox)", NULL);
        } else {
            report_add(&rep, SEV_MEDIUM, "envguard",
                       "virtualized environment confirmed "
                       "(legitimate use: cloud gaming, CI, dev)", NULL);
        }
    }
    if (env & ENVGUARD_CONTAINER) {
        report_add(&rep, SEV_INFO, "envguard",
                   "containerized environment detected", NULL);
    }

    if (telemetry_sim) {
        telemetry_run_simulation(&rep);
    }

    if (ebpf_mon) {
        ebpf_monitor_t mon;
        if (ebpf_monitor_init(&mon, &rep) == 0) {
            report_add(&rep, SEV_INFO, "ebpf",
                       "kernel monitor running; watching for cross-process "
                       "memory access (Ctrl-C to stop)", NULL);
            ebpf_monitor_run(&mon, watch_time);
            ebpf_monitor_cleanup(&mon);
            report_add(&rep, SEV_INFO, "ebpf",
                       "kernel monitor stopped", NULL);
        }
    }

    if (manifest_path) {
        if (access(manifest_path, R_OK) == 0) {
            integrity_verify_manifest(&rep, manifest_path);
        } else {
            report_add(&rep, SEV_LOW, "integrity",
                       "baseline manifest not found", manifest_path);
        }
    }

    memguard_t mg;
    if (memguard_init(&mg, watch_interval, &rep) == 0) {
        if (watch || selftest) {
            signal(SIGINT, on_signal);
            signal(SIGTERM, on_signal);

            if (memguard_start(&mg) == 0) {
                report_add(&rep, SEV_INFO, "memguard",
                           "memory integrity monitor running", NULL);

                if (selftest) {
                    sleep(1);
                    memguard_selftest(&mg, &rep);
                    sleep(1);
                    memguard_stop(&mg);
                    report_add(&rep, SEV_INFO, "memguard",
                               "memory integrity monitor stopped", NULL);
                    char detail[64];
                    snprintf(detail, sizeof(detail), "violations=%d",
                             memguard_violations(&mg));
                    report_add(&rep, SEV_INFO, "memguard",
                               memguard_violations(&mg) > 0
                                   ? "selftest: live patch was detected"
                                   : "selftest: live patch was NOT detected",
                               detail);
                } else {
                    int elapsed = 0;
                    while ((watch_time == 0 || elapsed < watch_time) &&
                           !g_quit) {
                        sleep(1);
                        elapsed++;
                    }
                    memguard_stop(&mg);
                    report_add(&rep, SEV_INFO, "memguard",
                               "memory integrity monitor stopped", NULL);
                }
            }
        } else {
            int n = memguard_check_once(&mg, &rep);
            report_add(&rep, SEV_INFO, "memguard",
                       n == 0 ? "own code segment memory integrity verified"
                              : "own code segment memory integrity violation",
                       NULL);
        }
    }

    network_shutdown();

    report_summary(&rep);
    return report_verdict(&rep);
}
