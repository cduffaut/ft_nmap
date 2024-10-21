#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

// servent structure is used to hold information about network services,
// including the service name, the port number, and protocol details.
static char    *get_service_name(int port, bool scan)
{
    struct servent  *service;

    if (scan == true)
        service = getservbyport(htons(port), "udp");
    else
        service = getservbyport(htons(port), "tcp");
    if (service)
    {
        return (service->s_name);
    }
    return NULL;
}

char    *scan_in_str(int scan)
{
    switch (scan)
    {
    case SYN:
        return ("SYN");
    case NUL:
        return ("NULL");
    case FIN:
        return ("FIN");
    case XMAS:
        return ("XMAS");
    case ACK:
        return ("ACK");
    case UDP:
        return ("UDP");
    default:
        return ("UNKNOWN");
    }
    return ("UNKNOWN");
}

char    *state_in_str(int state)
{
    switch (state)
    {
    case CLOSED:
        return "Closed";
    case OPEN:
        return "Open";
    case FILTERED:
        return "Filtered";
    case UNFILTERED:
        return "Unfiltered";
    case OPENFILTERED:
        return "Open|Filtered";
    default:
        return "Unknown";
    }
    return "Unknown";
}

static void     print_header()
{
    printf ("Port\t\tService Name (if applicable)\tResults\t\t\t\t\t\t\tConclusion\n");
    printf ("-----------------------------------------------------------------------------------------------------------------------\n");  
}

// check if one of the scans result for the port is: open
static bool     is_open(t_ip *ip, int port)
{
    for (int scan = 1; scan < TOTAL_TYPE; scan++)
    {
        if (ip->state[scan][port] == OPEN)
            return (true);
    }
    return (false);
}

static void     print_ports_state(t_ip *ip, int port, char *state)
{
    int printed = 0;

    for (int scan = 1; scan < TOTAL_TYPE; scan++)
    {
        if (list->info_scan[scan])
        {
            if (printed == 3 || printed == 5)
                printf ("\n\t\t\t\t\t\t");
            printf (("%s(%s) "), scan_in_str(scan), state_in_str(ip->state[scan][port]));
            printed++;
        }
    }
    printf("\t\t\t\t\t%s\n", state);
}

static void     display_close_stat(t_ip *ip, int port, bool first)
{
    char    *service_name = get_service_name(port, list->info_scan[UDP]);

    if (!service_name)
        service_name = "Unassigned";
    if (first)
    {
        printf ("Closed/Filtered/Unfiltered ports:\n");
        print_header();
    }
    printf("%d", port);
    printf("\t\t");
    printf("%s", service_name);
    printf ("\t\t\t");
    print_ports_state(ip, port, "Closed");
}

static void     print_close(t_ip *ip)
{
    bool    first = true;

    for (int port = 0; port < 65536; port++) // go through all the ports
    {
        if (list->info_port[port] == true) // if port is true
        {
            // print it in the close section if open came to be false
            if (is_open(ip, port) == false)
            {
                display_close_stat(ip, port, first);
                first = false;
            }
        }
    }
    printf ("\n");
}

static void     display_open_stat(t_ip *ip, int port, bool first)
{
    char    *service_name = get_service_name(port, list->info_scan[UDP]);
    if (!service_name)
        service_name = "Unassigned";
    if (first)
    {
        printf ("Open ports:\n");
        print_header();
    }
    printf("%d", port);
    printf("\t\t");
    printf(service_name);
    printf ("\t\t\t");
    print_ports_state(ip, port, "Open");
}

static void    print_open(t_ip *ip)
{
    bool    first = true;
    printf ("IP address: %s\n", ip->hostname);
    for (int port = 0; port < 65536; port++) // go through all the ports
    {
        if (list->info_port[port] == true) // if port is true
        {
            // print it in the open section if open came to be true
            if (is_open(ip, port) == true)
            {
                display_open_stat(ip, port, first);
                first = false;
            }
        }
    }
    printf ("\n");
}

// print in the right side the port and its result in function of if it is open or not 
static void print_by_state(t_ip *ip)
{
    print_open(ip);
    print_close(ip);
}

// send to the dispach function all the ips scannned
void    print_result()
{
    // go through all the ips scanned
    for (t_ip *tmp = list->res; tmp; tmp = tmp->next)
    {
        print_by_state(tmp);
    }
}