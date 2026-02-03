/**
 * platform.hpp - Platform fixups for IDA SDK compatibility
 *
 * macOS Mach kernel headers define processor_t and token_t as integer
 * typedefs (via <mach/machine_types.h>), which conflict with IDA SDK's
 * struct processor_t. Since #undef cannot remove typedefs, we redirect
 * them via #define before any system headers are included.
 *
 * Usage (every header or .cpp that includes both system and IDA headers):
 *
 *   #include <idasql/platform.hpp>        // FIRST: redirect macOS typedefs
 *   #include <system_or_library_header>    // system headers see harmless names
 *   #include <idasql/platform_undef.hpp>  // clean up before IDA headers
 *   #include <ida.hpp>                     // IDA sees clean namespace
 */

#pragma once

#ifdef __APPLE__
#define processor_t __mach_processor_t
#define token_t __mach_token_t
#endif
