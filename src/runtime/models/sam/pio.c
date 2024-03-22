/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/models/sam/pio.h>

/* ##############   Globals    ############## */
/* Array to hold the state of the GPIO pins. Each entry corresponds to a port,
 * each port holds a number of pins and whether they're input or output pins. */
sam_gpio_port_t sam_gpio_ports[NUM_GPIO_PORTS];
