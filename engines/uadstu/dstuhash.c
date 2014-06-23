/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

/* Probably, this is the most cross-platform way to include gost code
 * in our engine. If the library is compiled without gost engine or
 * engines are in separate dynamic libraries then we will have our own
 * independent copy of the code. If the library is compiled statically
 * with gost engine then we rely on linker to remove duplicate code */

#include "../ccgost/gosthash.h"

#include "../ccgost/gosthash.c"
