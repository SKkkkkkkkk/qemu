#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/sysbus.h"
#include "target/riscv/cpu.h"
#include "hw/riscv/numa.h"

enum {
    RHEA_A511_BOOTROM,
    RHEA_A511_SRAM,
    RHEA_A511_L2C,
    RHEA_A511_PLIC,
    RHEA_A511_PLICSW,
    RHEA_A511_UART0,
    RHEA_A511_DRAM,
};

static const MemMapEntry rhea_a511_memmap[] = {
    [RHEA_A511_BOOTROM] = {0x00000000, 256 * KiB},
    [RHEA_A511_SRAM]    = {0x00100000, 512 * KiB},
    [RHEA_A511_L2C]     = {0x00200000, 0x100000}, // andes l2c
    [RHEA_A511_PLIC]    = {0x00400000, 0x400000}, // andes plic
    [RHEA_A511_PLICSW]  = {0x00800000, 0x400000}, // andes plic_sw
    [RHEA_A511_UART0]   = {0x06000000, 4 * KiB}, // ns16550a compatible
    [RHEA_A511_DRAM]    = {0x40000000, 3 * GiB},
};

static void rhea_a511_machine_init(MachineState *machine)
{
    printf("rhea_a511_machine_init\n");
    (void)rhea_a511_memmap;

}

static void rhea_a511_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "RISC-V Board compatible with Rhea A511";
    mc->init = rhea_a511_machine_init;
    mc->max_cpus = 8;
    mc->default_cpu_type = TYPE_RISCV_CPU_BASE;
    mc->possible_cpu_arch_ids = riscv_numa_possible_cpu_arch_ids;
    mc->cpu_index_to_instance_props = riscv_numa_cpu_index_to_props;
    mc->get_default_cpu_node_id = riscv_numa_get_default_cpu_node_id;
    mc->numa_mem_supported = false;
}

static void rhea_a511_machine_instance_init(Object *obj)
{
    printf("rhea_a511_machine_instance_init\n");
}

static const TypeInfo rhea_a511_machine_type_info = {
    .name = MACHINE_TYPE_NAME("rhea_a511"),
    .parent = TYPE_MACHINE,
    .class_init = rhea_a511_machine_class_init,
    .instance_init = rhea_a511_machine_instance_init, // is this really needed?
    // .instance_size = sizeof(RheaA511MachineState),
};

static void rhea_a511_machine_register_types(void)
{
    type_register_static(&rhea_a511_machine_type_info);
}
type_init(rhea_a511_machine_register_types)
