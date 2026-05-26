#ifndef DEMON_COMMAND_CONFIG_H
#define DEMON_COMMAND_CONFIG_H

#include <core/Parser.h>

VOID CommandSleep( IN PPARSER DataArgs );
VOID CommandJob( IN PPARSER DataArgs );
VOID CommandConfig( IN PPARSER DataArgs );
VOID CommandScreenshot( IN PPARSER DataArgs );
VOID CommandTransfer( IN PPARSER DataArgs );
VOID CommandMemFile( IN PPARSER DataArgs );
VOID CommandKerberos( IN PPARSER DataArgs );

#endif
