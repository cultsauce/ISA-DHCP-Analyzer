#include "dhcp-stats.hpp"
#include <signal.h>

DHCPAnalyzer *analyzer = nullptr;

void handler(int signum) {
    endwin();

    if (analyzer != nullptr) {
        analyzer->quit(EXIT_SUCCESS);
        delete analyzer;
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handler);
    char *filename = nullptr;
    char *interface = nullptr;
    std::vector<const char *> prefixes = {};

    int opt;
    while ((opt = getopt(argc, argv, ":r:i:")) != -1) {
        switch (opt) {
        case 'i': {
            interface = optarg;
            break;
        }
        case 'r': {
            filename = optarg;
            break;
        }
        case '?':
        case ':': {
            fprintf(stderr, "usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
            break;
        }
        }
    }

    for (; optind < argc; optind++) {
        prefixes.push_back(argv[optind]);
    }

    if ((filename == nullptr && interface == nullptr) || (filename != nullptr && interface != nullptr)) {
        fprintf(stderr, "usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
        exit(EXIT_FAILURE);
    }

    analyzer = new DHCPAnalyzer();
    if (analyzer->initialize(filename, interface, prefixes) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    openlog("dhcp-stats.log", LOG_PID, LOG_USER);

    /* prepare ncurses */
    initscr();
    printw("IP-Prefix\tMax-hosts\tAllocated addresses\tUtilization\n");
    refresh();
    int res;
    int exceeded = 0;
    while ((res = analyzer->next()) == EXIT_SUCCESS) {
        for (int i = 0; i < analyzer->subnet_stats.size(); i++) {
            mvprintw(i + 2, 0, "%s/%u\t%u\t%u\t%.2f%\n", inet_ntoa(analyzer->subnet_stats[i].net_addr),
                     analyzer->subnet_stats[i].prefix,
                     analyzer->subnet_stats[i].max_alloc,
                     analyzer->subnet_stats[i].allocated,
                     analyzer->subnet_stats[i].get_percentage());

            /* write to syslog if the current subnet exceeded 50% of possible allocations */
            if (analyzer->subnet_stats[i].get_percentage() >= 50.0 && !analyzer->subnet_stats[i].exceeded_half) {
                analyzer->subnet_stats[i].exceeded_half = true;

                syslog(LOG_INFO, "prefix %s/%u exceeded 50%% of allocations", inet_ntoa(analyzer->subnet_stats[i].net_addr),
                       analyzer->subnet_stats[i].prefix);
                mvprintw(analyzer->subnet_stats.size() + 3 + exceeded, 0, "prefix %s/%u exceeded 50%% of allocations", inet_ntoa(analyzer->subnet_stats[i].net_addr),
                         analyzer->subnet_stats[i].prefix);
                exceeded += 1;
            }
            refresh();
        }
    }
    closelog();
    analyzer->quit(EXIT_SUCCESS);

    while (true)
        ;
}