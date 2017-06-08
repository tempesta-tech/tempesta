/*
 * This program is derived from systemd.
 *
 * Copyright 2011 Lennart Poettering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define streq(a, b) (!strcmp(a, b))
#define ELEMENTSOF(a) (sizeof(a) / sizeof((a)[0]))

enum {
	VIRTUALIZATION_NONE,
	VIRTUALIZATION_VM_OTHER,
	VIRTUALIZATION_MICROSOFT,
};

static int detect_vm_cpuid(void) {

        static const struct {
                const char *cpuid;
                int id;
        } cpuid_vendor_table[] = {
                /* http://msdn.microsoft.com/en-us/library/ff542428.aspx */
                { "Microsoft Hv", VIRTUALIZATION_MICROSOFT },
        };

        uint32_t eax, ecx;
        bool hypervisor;

        /* http://lwn.net/Articles/301888/ */

#if defined (__i386__)
#define REG_a "eax"
#define REG_b "ebx"
#elif defined (__amd64__)
#define REG_a "rax"
#define REG_b "rbx"
#endif

        /* First detect whether there is a hypervisor */
        eax = 1;
        __asm__ __volatile__ (
                /* ebx/rbx is being used for PIC! */
                "  push %%"REG_b"         \n\t"
                "  cpuid                  \n\t"
                "  pop %%"REG_b"          \n\t"

                : "=a" (eax), "=c" (ecx)
                : "0" (eax)
        );

        hypervisor = !!(ecx & 0x80000000U);

        if (hypervisor) {
                union {
                        uint32_t sig32[3];
                        char text[13];
                } sig = {};
                unsigned j;

                /* There is a hypervisor, see what it is */
                eax = 0x40000000U;
                __asm__ __volatile__ (
                        /* ebx/rbx is being used for PIC! */
                        "  push %%"REG_b"         \n\t"
                        "  cpuid                  \n\t"
                        "  mov %%ebx, %1          \n\t"
                        "  pop %%"REG_b"          \n\t"

                        : "=a" (eax), "=r" (sig.sig32[0]), "=c" (sig.sig32[1]), "=d" (sig.sig32[2])
                        : "0" (eax)
                );

                for (j = 0; j < ELEMENTSOF(cpuid_vendor_table); j ++)
                        if (streq(sig.text, cpuid_vendor_table[j].cpuid))
                                return cpuid_vendor_table[j].id;

                return VIRTUALIZATION_VM_OTHER;
        }

        return VIRTUALIZATION_NONE;
}

int main(void)
{
	return detect_vm_cpuid() != VIRTUALIZATION_MICROSOFT;
}
