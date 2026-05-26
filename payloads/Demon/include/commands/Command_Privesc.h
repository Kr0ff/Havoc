#ifndef DEMON_COMMAND_PRIVESC_H
#define DEMON_COMMAND_PRIVESC_H

#include <core/Parser.h>

/* Dispatch privilege-escalation sub-commands (UAC bypass via fodhelper, computerdefaults, eventvwr). */
VOID CommandPrivesc( IN PPARSER DataArgs );

#endif
