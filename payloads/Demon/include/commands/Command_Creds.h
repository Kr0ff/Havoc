#ifndef DEMON_COMMAND_CREDS_H
#define DEMON_COMMAND_CREDS_H

#include <core/Parser.h>

/* Dispatch credential-access sub-commands (lsass dump, SAM/SECURITY/SYSTEM hive save). */
VOID CommandCreds( IN PPARSER DataArgs );

#endif
