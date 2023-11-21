/*
** file: main.cpp
** desc: argument parsing, statistics visualization
** author : xkubin27 (Tereza Kubincova)
*/

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
    signal(SIGTERM, handler);
    signal(SIGKILL, handler);
    char *filename = nullptr;
    char *interface = nullptr;
    std::vector<const char *> prefixes = {};

    int opt;
    while ((opt = getopt(argc, argv, ":hr:i:")) != -1) {
        switch (opt) {
        case 'h': {
            fprintf(stdout, "usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
            exit(EXIT_SUCCESS);
        }
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
            exit(EXIT_FAILURE);
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
    curs_set(0);
    mvprintw(0, 0, "IP-Prefix");
    mvprintw(0, 20, "Max-hosts");
    mvprintw(0, 40, "Allocated addresses");
    mvprintw(0, 70, "Utilization");

    refresh();
    int res;
    int exceeded = 0, start = 0;
    while (!start || (res = analyzer->next()) == EXIT_SUCCESS) {
        start = 1;
        for (int i = 0; i < analyzer->subnet_stats.size(); i++) {
            mvprintw(i + 2, 0, "%s/%u", inet_ntoa(analyzer->subnet_stats[i].net_addr),
                     analyzer->subnet_stats[i].prefix);
            mvprintw(i + 2, 20, "%u", analyzer->subnet_stats[i].max_alloc);
            mvprintw(i + 2, 40, "%u", analyzer->subnet_stats[i].allocated);
            mvprintw(i + 2, 70, "%.2f%%", analyzer->subnet_stats[i].get_percentage());

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