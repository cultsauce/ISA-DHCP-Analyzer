#include "dhcp-stats.hpp"

int main(int argc, char *argv[]) {
    char *filename = nullptr;
    char *interface = nullptr;
    std::vector<const char *> prefixes = {};

    for (int i = 1; i < argc; i++) {

        std::string arg = (std::string)argv[i];
        if (arg == "-r") {
            filename = argv[++i];
        } else if (arg == "-i") {
            interface = argv[++i];
        } else {
            prefixes.push_back(argv[i]);
        }
    }

    if ((filename == nullptr && interface == nullptr) || (filename != nullptr && interface != nullptr)) {
        fprintf(stderr, "usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
        exit(EXIT_FAILURE);
    }

    DHCPAnalyzer analyzer;
    if (analyzer.initialize(filename, interface, prefixes) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    openlog("dhcp-stats.log", LOG_PID, LOG_USER);

    /* prepare ncurses */
    initscr();
    printw("IP-Prefix\tMax-hosts\tAllocated addresses\tUtilization\n");
    refresh();
    while (analyzer.next() == EXIT_SUCCESS) {

        for (int i = 0; i < analyzer.subnet_stats.size(); i++) {
            mvprintw(i + 2, 0, "%s/%u\t%u\t%u\t%.2f%\n", inet_ntoa(analyzer.subnet_stats[i].net_addr),
                     analyzer.subnet_stats[i].prefix,
                     analyzer.subnet_stats[i].max_alloc,
                     analyzer.subnet_stats[i].allocated,
                     analyzer.subnet_stats[i].get_percentage());

            /* write to syslog if the current subnet exceeded 50% of possible allocations */
            if (analyzer.subnet_stats[i].get_percentage() >= 0.5) {
                syslog(LOG_INFO, "prefix %s/%u exceeded 50%% of allocations", inet_ntoa(analyzer.subnet_stats[i].net_addr),
                       analyzer.subnet_stats[i].prefix);
            }
            refresh();
        }
    }
    closelog();
    analyzer.quit(EXIT_SUCCESS);

    while (getchar() != 'q')
        ;
    endwin();
    return EXIT_SUCCESS;
}