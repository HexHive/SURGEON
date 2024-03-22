/* ##############   Includes   ############## */
#include <surgeon/context.h>
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <string.h>

/* ##############   typedefs   ############## */
typedef struct surgeontarget_s {
    /* clang-format off */
    PyObject_HEAD
    context_t *context_ptr;
    /* clang-format on */
} SURGEONTarget;

/* #########   Function signatures   ######## */
static int SURGEONTarget_init(SURGEONTarget *self, PyObject UNUSED *args,
                                PyObject UNUSED *kwds);
static void SURGEONTarget_dealloc(SURGEONTarget *self);
static PyObject *SURGEONTarget_getattr(SURGEONTarget *self, PyObject *attr);
static int SURGEONTarget_setattr(SURGEONTarget *self, PyObject *attr,
                                   PyObject *value);
static PyObject *SURGEONTarget_read_register(SURGEONTarget *self,
                                               PyObject *reg);
static PyObject *SURGEONTarget_write_register(SURGEONTarget *self,
                                                PyObject *const *args,
                                                Py_ssize_t nargs);
static PyObject *SURGEONTarget_read_memory(SURGEONTarget UNUSED *self,
                                             PyObject *args, PyObject *kwargs);
static PyObject *SURGEONTarget_write_memory(SURGEONTarget UNUSED *self,
                                              PyObject *args, PyObject *kwargs);
static PyObject *SURGEONTarget_get_arg(SURGEONTarget *self, PyObject *idx);
static PyObject *SURGEONTarget_set_arg(SURGEONTarget *self, PyObject *args);
static PyObject *SURGEONTarget_add_timer(SURGEONTarget UNUSED *self,
                                           PyObject *args);
static PyObject *SURGEONTarget_attach_irq(SURGEONTarget UNUSED *self,
                                            PyObject *const *args,
                                            Py_ssize_t nargs);
static PyObject *SURGEONTarget_start_timer(SURGEONTarget UNUSED *self,
                                             PyObject *idx);
static PyObject *SURGEONTarget_stop_timer(SURGEONTarget UNUSED *self,
                                            PyObject *idx);
static PyObject *SURGEONTarget_get_timer_val(SURGEONTarget UNUSED *self,
                                               PyObject *idx);
static PyObject *SURGEONTarget_set_timer_val(SURGEONTarget UNUSED *self,
                                               PyObject *const *args,
                                               Py_ssize_t nargs);

/* ##########   Global variables   ########## */
context_t fw_context = {0};
uintptr_t runtime_sp = 0;

/* Definition of the surgeon module */
static PyModuleDef surgeonmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "surgeon",
    .m_doc =
        "SURGEON module that provides a target for the HALucinator handlers.",
    .m_size = -1,
};

/* Methods provided by the SURGEONTarget class */
static PyMethodDef SURGEONTarget_methods[] = {
    {"read_register", (PyCFunction)SURGEONTarget_read_register, METH_O,
     "Gets a firmware register's contents"},
    {"write_register", (PyCFunction)SURGEONTarget_write_register,
     METH_FASTCALL, "Sets a firmware register to the given value"},
    {"read_memory", (PyCFunction)SURGEONTarget_read_memory,
     METH_VARARGS | METH_KEYWORDS, "Reads firmware memory contents"},
    {"write_memory", (PyCFunction)SURGEONTarget_write_memory,
     METH_VARARGS | METH_KEYWORDS, "Writes firmware memory contents"},
    {"get_arg", (PyCFunction)SURGEONTarget_get_arg, METH_O,
     "Gets the value for a function argument (zero indexed)"},
    {"set_arg", (PyCFunction)SURGEONTarget_set_arg, METH_VARARGS,
     "Sets the value for a function argument (zero indexed)"},
    {"add_timer", (PyCFunction)SURGEONTarget_add_timer, METH_VARARGS,
     "Add a timer to the current runtime"},
    {"attach_irq", (PyCFunction)SURGEONTarget_attach_irq, METH_FASTCALL,
     "Attaches an IRQ to a timer in the runtime (zero indexed)"},
    {"start_timer", (PyCFunction)SURGEONTarget_start_timer, METH_O,
     "Starts a timer in the runtime (zero indexed)"},
    {"stop_timer", (PyCFunction)SURGEONTarget_stop_timer, METH_O,
     "Stops a timer in the runtime (zero indexed)"},
    {"get_timer_val", (PyCFunction)SURGEONTarget_get_timer_val, METH_O,
     "Gets the tick value for a timer in the runtime (zero indexed)"},
    {"set_timer_val", (PyCFunction)SURGEONTarget_set_timer_val, METH_FASTCALL,
     "Sets the tick value for a timer in the runtime (zero indexed)"},
    {NULL}, /* Sentinel */
};

/*
 * Definition of the SURGEONTarget class
 * Check the SURGEONTarget_{get,set}attr functions for information on how to
 * interact with the class (attribute getters/setters that modify the internal
 * context)
 */
static PyTypeObject SURGEONTargetType = {
    /* clang-format off */
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "surgeon.SURGEONTarget",
    /* clang-format on */
    .tp_doc = PyDoc_STR("SURGEON handler targets"),
    .tp_basicsize = sizeof(SURGEONTarget),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_dict = NULL,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)SURGEONTarget_init,
    .tp_dealloc = (destructor)SURGEONTarget_dealloc,
    .tp_methods = SURGEONTarget_methods,
    .tp_getattro = (getattrofunc)SURGEONTarget_getattr,
    .tp_setattro = (setattrofunc)SURGEONTarget_setattr,
};

/**
 * @brief Initialize the surgeon module
 *
 * Initializes the surgeon module and makes surgeon.SURGEONTarget
 * available for import from Python scripts.
 *
 * @return PyMODINIT_FUNC PyObject pointer to the module
 */
PyMODINIT_FUNC PyInit_surgeon(void) {
    PyObject *mod;
    if (PyType_Ready(&SURGEONTargetType) < 0)
        return NULL;

    mod = PyModule_Create(&surgeonmodule);
    if (mod == NULL)
        return NULL;

    Py_INCREF(&SURGEONTargetType);
    if (PyModule_AddObject(mod, "SURGEONTarget",
                           (PyObject *)&SURGEONTargetType)
        < 0) {
        Py_DECREF(&SURGEONTargetType);
        Py_DECREF(mod);
        return NULL;
    }

    return mod;
}

/**
 * @brief Initialize an SURGEONTarget object
 *
 * Sets the SURGEONTarget object's context pointer to the global context to
 * achieve a mapping of this global context from the C to the Python world.
 *
 * @param self Reference to Python object to initialize
 * @param args Positional arguments passed to __init__()
 * @param kwds Keyword arguments passed to __init__()
 * @return int 0 in case of success
 */
static int SURGEONTarget_init(SURGEONTarget *self, PyObject UNUSED *args,
                                PyObject UNUSED *kwds) {
    self->context_ptr = &fw_context;
    return 0;
}

/**
 * @brief Deallocate an SURGEONTarget object
 *
 * Frees the memory associatied with an SURGEONTarget object.
 *
 * @param self Reference to Python object to free
 */
static void SURGEONTarget_dealloc(SURGEONTarget *self) {
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/**
 * @brief Get an attribute for an SURGEONTarget object
 *
 * Maps Python object attributes to the underlying context's fields. This allows
 * accessing the firmware's registers as follows (assuming target is an object
 * of type SURGEONTarget): content_reg_r0 = target.r0
 *
 * @param self Reference to the Python object the attribute is requested from
 * @param attr Reference to a PyObject containing the attribute name
 * @return PyObject* The requested attribute's value
 */
static PyObject *SURGEONTarget_getattr(SURGEONTarget *self,
                                         PyObject *attr) {
    PyObject *ret = NULL;

    /* Convert attribute name to C string */
    const char *reg = PyUnicode_AsUTF8(attr);

    /* Retrieve the corresponding register (if it's a valid one) */
    if (strcmp(reg, "r0") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r0);
    } else if (strcmp(reg, "r1") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r1);
    } else if (strcmp(reg, "r2") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r2);
    } else if (strcmp(reg, "r3") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r3);
    } else if (strcmp(reg, "r4") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r4);
    } else if (strcmp(reg, "r5") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r5);
    } else if (strcmp(reg, "r6") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r6);
    } else if (strcmp(reg, "r7") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r7);
    } else if (strcmp(reg, "r8") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r8);
    } else if (strcmp(reg, "r9") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r9);
    } else if (strcmp(reg, "r10") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r10);
    } else if (strcmp(reg, "r11") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r11);
    } else if (strcmp(reg, "r12") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->r12);
    } else if (strcmp(reg, "r13") == 0 || strcmp(reg, "sp") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->sp);
    } else if (strcmp(reg, "r14") == 0 || strcmp(reg, "lr") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->lr);
    } else if (strcmp(reg, "r15") == 0 || strcmp(reg, "pc") == 0) {
        ret = PyLong_FromSsize_t((Py_ssize_t)self->context_ptr->pc);
    } else {
        ret = PyObject_GenericGetAttr((PyObject *)self, attr);
    }

    return ret;
}

/**
 * @brief Set an attribute for an SURGEONTarget object
 *
 * Maps Python object attributes to the underlying context's fields. This allows
 * setting the firmware's registers as follows (assuming target is an object
 * of type SURGEONTarget): target.r0 = 0xffffffff
 *
 * @param self Reference to the Python object the attribute is set for
 * @param attr Reference to a PyObject containing the attribute name
 * @param value Reference to a PyObject holding the value to be set
 * @return int -1 on error, 0 on success
 */
static int SURGEONTarget_setattr(SURGEONTarget *self, PyObject *attr,
                                   PyObject *value) {
    PyObject *err = NULL;
    /* Convert attribute name to C string, attribute value to uint32_t */
    const char *reg = PyUnicode_AsUTF8(attr);
    const uint32_t val = (uint32_t)PyLong_AsLong(value);

    if ((val == (uint32_t)-1) && (err = PyErr_Occurred()) != NULL) {
        /* Error occured during conversion */
        PyErr_Format(err,
                     "'SURGEONTarget' attribute '%.400s' could not be set: "
                     "invalid value",
                     reg);
        return -1;
    } else if (strcmp(reg, "r0") == 0) {
        self->context_ptr->r0 = val;
    } else if (strcmp(reg, "r1") == 0) {
        self->context_ptr->r1 = val;
    } else if (strcmp(reg, "r2") == 0) {
        self->context_ptr->r2 = val;
    } else if (strcmp(reg, "r3") == 0) {
        self->context_ptr->r3 = val;
    } else if (strcmp(reg, "r4") == 0) {
        self->context_ptr->r4 = val;
    } else if (strcmp(reg, "r5") == 0) {
        self->context_ptr->r5 = val;
    } else if (strcmp(reg, "r6") == 0) {
        self->context_ptr->r6 = val;
    } else if (strcmp(reg, "r7") == 0) {
        self->context_ptr->r7 = val;
    } else if (strcmp(reg, "r8") == 0) {
        self->context_ptr->r8 = val;
    } else if (strcmp(reg, "r9") == 0) {
        self->context_ptr->r9 = val;
    } else if (strcmp(reg, "r10") == 0) {
        self->context_ptr->r10 = val;
    } else if (strcmp(reg, "r11") == 0) {
        self->context_ptr->r11 = val;
    } else if (strcmp(reg, "r12") == 0) {
        self->context_ptr->r12 = val;
    } else if (strcmp(reg, "r13") == 0 || strcmp(reg, "sp") == 0) {
        self->context_ptr->sp = val;
    } else if (strcmp(reg, "r14") == 0 || strcmp(reg, "lr") == 0) {
        self->context_ptr->lr = val;
    } else if (strcmp(reg, "r15") == 0 || strcmp(reg, "pc") == 0) {
        PyErr_Format(PyExc_RuntimeError,
                     "Attribute '%.400s' is read-only, set 'lr' to control the "
                     "firmware's continuation point",
                     reg);
    } else {
        PyErr_Format(PyExc_RuntimeError,
                     "'SURGEONTarget' objects do not allow setting arbitrary "
                     "attributes",
                     reg);
        return -1;
    }
    return 0;
}

/**
 * @brief Read a register value
 *
 * Retrieves the register value via the object's attribute.
 *
 * @param self Reference to the Python object on which the method was called
 * @param reg Reference to a PyObject containing the register name
 * @return PyObject* The requested register's value
 */
static PyObject *SURGEONTarget_read_register(SURGEONTarget *self,
                                               PyObject *reg) {
    return SURGEONTarget_getattr(self, reg);
}

/**
 * @brief Write a register value
 *
 * Sets a register value via the object's attribute.
 * Required arguments:
 *  - register to write (type str)
 *  - value to set (type int)
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Reference to a list of arguments for the method
 * @param nargs Number of arguments to the method
 * @return PyObject* False on error, True on success
 */
static PyObject *SURGEONTarget_write_register(SURGEONTarget *self,
                                                PyObject *const *args,
                                                Py_ssize_t nargs) {
    /* Check number of arguments */
    if (nargs != 2) {
        PyErr_Format(PyExc_RuntimeError,
                     "Invalid number of arguments to 'read_register'");
    }

    /* Actually write the register */
    int success = SURGEONTarget_setattr(self, args[0], args[1]);

    if (success == 0) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

/**
 * @brief Convert data at a specific memory location into a PyLong object
 *
 * Reads data from the given address and converts it to a PyLong. This function
 * mainly serves as a helper for other functions in order to reduce code
 * duplication.
 * The parameter word_size has 4 valid values:
 *  - 1 = byte
 *  - 2 = halfword
 *  - 4 = word
 *  - 8 = doubleword
 *
 * @param address Address to read from
 * @param word_size Word size to read
 * @return PyObject* PyLong object holding the read data
 */
static inline PyObject *mem_to_pylong(const char *address, size_t word_size) {
    /* Read memory depending on given word size */
    unsigned long long val = 0;
    switch (word_size) {
        case 1: {
            val = (unsigned long long)*((uint8_t *)address);
            break;
        }
        case 2: {
            val = (unsigned long long)*((uint16_t *)address);
            break;
        }
        case 4: {
            val = (unsigned long long)*((uint32_t *)address);
            break;
        }
        case 8: {
            val = (unsigned long long)*((uint64_t *)address);
            break;
        }
        default: {
            PyErr_Format(PyExc_RuntimeError, "Invalid word size given: %zd",
                         word_size);
            return NULL;
        }
    }

    /* Convert the read memory to a Python object */
    return PyLong_FromUnsignedLongLong(val);
}

/**
 * @brief Read firmware memory
 *
 * Reads data from the given address. By default, unpacks the data into a tuple
 * of byte-sized integers. The integer size can however be adapted, and memory
 * can also simply be returned as a bytes object.
 * Required arguments:
 *  - address to read from (type int)
 *  - size of the object to read (type int)
 * Optional arguments:
 *  - number of words of the above size to read (type int)
 *  - flag whether to unpack into tuple of integers or return bytes (type bool)
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Reference to a list of positional arguments for the method
 * @param kwargs Reference to a list of keyword arguments for the method
 * @return PyObject* Tuple, int, or bytes containing the read data
 */
static PyObject *SURGEONTarget_read_memory(SURGEONTarget UNUSED *self,
                                             PyObject *args, PyObject *kwargs) {
    const char *address = NULL;
    size_t size = 0;
    size_t num_words = 1; /* By default, read one word of the above size */
    int raw = (int)false; /* By default, unpack data into tuple of integers.
                             Cannot use type bool here because the Python API
                             expects an int */

    /* Parse the arguments: address and size are required, num_words and raw
     * are optional and set to the above defaults */
    static char *keywords[] = {"address", "size", "num_words", "raw", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "nn|np:read_memory",
                                     keywords, &address, &size, &num_words,
                                     &raw)) {
        return NULL;
    }

    if (raw == true) {
        /* Just return a bytes object */
        return PyBytes_FromStringAndSize(address, size * num_words);
    } else {
        /* Unpack memory into integer/tuple of integers */
        if (num_words == 1) {
            /* Only one word => return PyLong */
            return mem_to_pylong(address, size);
        } else {
            /* Multiple words => return tuple of PyLongs */
            PyObject *tuple = PyTuple_New((Py_ssize_t)num_words);

            for (size_t i = 0; i < num_words; i++) {
                /* Read from memory */
                PyObject *py_val = mem_to_pylong(address, size);
                if (py_val == NULL) {
                    Py_DECREF(tuple);
                    return NULL;
                }
                /* Increment address for next read */
                address += size;

                /* Add the value to the tuple */
                if (PyTuple_SetItem(tuple, i, py_val) == -1) {
                    Py_DECREF(tuple);
                    return NULL;
                }
            }
            return tuple;
        }
    }
}

/**
 * @brief Convert a PyLong object into a C data type and write to memory
 *
 * Converts a PyLong to a C data type of the given word size and writes it to
 * memory. This function mainly serves as a helper for other functions in order
 * to reduce code duplication. The parameter word_size has 4 valid values:
 *  - 1 = byte
 *  - 2 = halfword
 *  - 4 = word
 *  - 8 = doubleword
 *
 * @param value PyLong to convert
 * @param address Address to write to
 * @param word_size Word size to write
 * @return bool false on error, true on success
 */
static inline bool pylong_to_mem(PyObject *value, char *address,
                                 size_t word_size) {
    /* Convert PyLong to unsigned long long */
    unsigned long long val = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return false;
    }

    /* Actually write to memory, depending on the given word size */
    switch (word_size) {
        case 1: {
            *((uint8_t *)address) = (uint8_t)val;
            break;
        }
        case 2: {
            *((uint16_t *)address) = (uint16_t)val;
            break;
        }
        case 4: {
            *((uint32_t *)address) = (uint32_t)val;
            break;
        }
        case 8: {
            *((uint64_t *)address) = (uint64_t)val;
            break;
        }
        default: {
            PyErr_Format(PyExc_RuntimeError, "Invalid word size given: %zd",
                         word_size);
            return false;
        }
    }

    return true;
}

/**
 * @brief Write firmware memory
 *
 * Writes data to the given address.
 * Required arguments:
 *  - address to write to (type int)
 *  - size of the object to write (type int)
 *  - value to write (type int, list, str, or bytes,
 *    depending on num_words and raw)
 * Optional arguments:
 *  - number of words of the above size to write (type int)
 *  - flag whether to interpret data as str/bytes or int/list (type bool)
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Reference to a list of positional arguments for the method
 * @param kwargs Reference to a list of keyword arguments for the method
 * @return PyObject* False on error, True on success
 */
static PyObject *SURGEONTarget_write_memory(SURGEONTarget UNUSED *self,
                                              PyObject *args,
                                              PyObject *kwargs) {
    char *address = NULL;
    size_t size = 0;
    PyObject *value = NULL;
    size_t num_words = 1; /* By default, write one word of the above size */
    int raw = (int)false; /* By default, expect int/tuple of ints.
                             Cannot use type bool here because the Python API
                             expects an int */

    /* Parse the arguments: address, size and value are required, num_words and
     * raw are optional and set to the above defaults */
    static char *keywords[] = {"address",   "size", "value",
                               "num_words", "raw",  NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "knO|np:write_memory",
                                     keywords, &address, &size, &value,
                                     &num_words, &raw)) {
        Py_RETURN_FALSE;
    }

    if (raw == true) {
        /* Convert the value to a string and copy it to memory */
        if (!PyBytes_Check(value) || (PyBytes_Size(value) < (Py_ssize_t)size)) {
            /* Not a bytes object / too little bytes passed */
            Py_RETURN_FALSE;
        }
        char *bytes = PyBytes_AsString(value);
        if (bytes == NULL) {
            /* No valid PyBytes object */
            Py_RETURN_FALSE;
        }
        /* Check if multiplication would overflow */
        if (num_words != 0 && size > SIZE_MAX / num_words) {
            Py_RETURN_FALSE;
        } else {
            /* Actually copy the bytes to the destination */
            memcpy((void *)address, (void *)bytes, size * num_words);
            Py_RETURN_TRUE;
        }
    } else {
        /* Convert value from int or list of ints and copy it to memory */
        if (num_words == 1) {
            /* Passed argument is a single integer */
            if (pylong_to_mem(value, address, size)) {
                Py_RETURN_TRUE;
            } else {
                Py_RETURN_FALSE;
            }
        } else {
            /* Passed argument is a list/tuple of integers */

            /* If list, convert to tuple to have a common interface below */
            if (PyList_Check(value)) {
                value = PyList_AsTuple(value);
            }

            /* Check whether it's actually a tuple and it is big enough */
            if (!PyTuple_Check(value)
                || (PyTuple_Size(value) < (Py_ssize_t)num_words)) {
                Py_RETURN_FALSE;
            }

            /* Actually write the values to memory */
            for (size_t i = 0; i < num_words; i++) {
                if (!pylong_to_mem(PyTuple_GetItem(value, i), address, size)) {
                    Py_RETURN_FALSE;
                }
                address += size;
            }

            Py_RETURN_TRUE;
        }
    }
}

/**
 * @brief Get a function call argument
 *
 * Retrieves a function call argument when called as self.get_arg(idx) on an
 * SURGEONTarget object, where idx is the zero-indexed index of the argument.
 * Retrieves arguments according to the following calling convention:
 *  - First 4 arguments are passed in r0 - r3
 *  - Any further arguments are passed on the stack
 *
 * @param self Reference to the Python object on which the method was called
 * @param idx Index of the argument to retrieve
 * @return PyObject* PyLong encoding the argument value
 */
static PyObject *SURGEONTarget_get_arg(SURGEONTarget *self, PyObject *idx) {
    Py_ssize_t index = PyLong_AsSsize_t(idx);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid argument index");
        return NULL;
    }

    if (index < 4) {
        /* Argument passed in register */
        return SURGEONTarget_read_register(
            self, PyUnicode_FromFormat("r%zd", index));
    } else {
        /* Argument passed on stack: offset (index - 4) * word_size */
        const char *addr = (const char *)self->context_ptr->sp
                           + ((index - 4) * sizeof(size_t));
        return mem_to_pylong(addr, sizeof(size_t));
    }
}

/**
 * @brief Set a function call argument
 *
 * Sets a function call argument when called as self.set_arg(idx) on an
 * SURGEONTarget object, where idx is the zero-indexed index of the argument.
 * Sets arguments according to the following calling convention:
 *  - First 4 arguments are passed in r0 - r3
 *  - Any further arguments are passed on the stack
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Reference to a list of positional arguments for the method
 * @return PyObject* PyNone
 */
static PyObject *SURGEONTarget_set_arg(SURGEONTarget *self,
                                         PyObject *args) {
    Py_ssize_t index = 0;
    PyObject *value = NULL;

    if (!PyArg_ParseTuple(args, "nO", &index, &value) || !PyLong_Check(value)) {
        Py_RETURN_NONE;
    }

    if (index < 0) {
        /* Invalid argument index */
        PyErr_Format(PyExc_ValueError, "Invalid argument index");
    } else if (index < 4) {
        /* Argument passed in register */
        PyObject *const reg_args[] = {PyUnicode_FromFormat("r%zd", index),
                                      value};
        SURGEONTarget_write_register(
            self, reg_args, (Py_ssize_t)(sizeof(reg_args) / sizeof(*reg_args)));
    } else {
        /* Argument passed on stack: offset (index - 4) * word_size */
        char *addr =
            (char *)self->context_ptr->sp + ((index - 4) * sizeof(size_t));
        pylong_to_mem(value, addr, sizeof(size_t));
    }

    Py_RETURN_NONE;
}

/**
 * @brief Add a timer to the current runtime
 *
 * This function is basically only a wrapper around our timer emulation.
 * It takes a reload value, resolution and the corresponding IRQ (== index into
 * the vector table) and creates a timer based on those.
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Reference to a list of positional arguments for the method
 * @return PyObject* Index of the newly added timer as PyLong
 */
static PyObject *SURGEONTarget_add_timer(SURGEONTarget UNUSED *self,
                                           PyObject *args) {
    uint64_t reload_val = 0;
    uint64_t resolution = 0;
    /* Parse arguments */
    if (!PyArg_ParseTuple(args, "KK", &reload_val, &resolution)) {
        /* Argument parsing failed => return -1 */
        return PyLong_FromLong(-1L);
    }

    size_t index = add_timer(reload_val, resolution);
    if (unlikely(index == (size_t)-1)) {
        /* Error adding timer => return -1 */
        return PyLong_FromLong(-1L);
    } else {
        /* Successfully added timer */
        return PyLong_FromSize_t(index);
    }
}

/**
 * @brief Attach an interrupt to a timer in the given runtime
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Arguments passed (the timer index and IRQ number)
 * @param nargs Number of arguments passed (supposed to be 2)
 * @return PyObject* PyNone
 */
static PyObject *SURGEONTarget_attach_irq(SURGEONTarget UNUSED *self,
                                            PyObject *const *args,
                                            Py_ssize_t nargs) {
    if (nargs != (Py_ssize_t)2) {
        PyErr_Format(PyExc_TypeError, "Wrong number of arguments");
        return NULL;
    }
    Py_ssize_t index = PyLong_AsSsize_t(args[0]);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid timer index");
        return NULL;
    }

    Py_ssize_t irq_num = PyLong_AsSsize_t(args[1]);
    if ((irq_num == -1 && PyErr_Occurred()) || (irq_num < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid IRQ number");
        return NULL;
    }

    /* Actually attach the interrupt to the timer */
    attach_irq(index, (uint32_t)irq_num);
    Py_RETURN_NONE;
}

/**
 * @brief Start a timer in the given runtime
 *
 * @param self Reference to the Python object on which the method was called
 * @param idx Index of the timer to start
 * @return PyObject* PyNone
 */
static PyObject *SURGEONTarget_start_timer(SURGEONTarget UNUSED *self,
                                             PyObject *idx) {
    Py_ssize_t index = PyLong_AsSsize_t(idx);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid timer index");
        return NULL;
    }
    /* Actually start the timer */
    start_timer(index);
    Py_RETURN_NONE;
}

/**
 * @brief Stop a timer in the given runtime
 *
 * @param self Reference to the Python object on which the method was called
 * @param idx Index of the timer to stop
 * @return PyObject* PyNone
 */
static PyObject *SURGEONTarget_stop_timer(SURGEONTarget UNUSED *self,
                                            PyObject *idx) {
    Py_ssize_t index = PyLong_AsSsize_t(idx);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid timer index");
        return NULL;
    }
    /* Actually start the timer */
    stop_timer(index);
    Py_RETURN_NONE;
}

/**
 * @brief Return a timer's value in the given runtime
 *
 * @param self Reference to the Python object on which the method was called
 * @param idx Index of the timer to return
 * @return PyObject* Value of the timer as PyLong
 */
static PyObject *SURGEONTarget_get_timer_val(SURGEONTarget UNUSED *self,
                                               PyObject *idx) {
    Py_ssize_t index = PyLong_AsSsize_t(idx);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid timer index");
        return NULL;
    }
    /* Actually return the timer */
    return PyLong_FromUnsignedLongLong(get_timer_val(index));
}

/**
 * @brief Set the tick value for a timer in the given runtime
 *
 * @param self Reference to the Python object on which the method was called
 * @param args Arguments passed (the timer index and tick value)
 * @param nargs Number of arguments passed (supposed to be 2)
 * @return PyObject* PyNone
 */
static PyObject *SURGEONTarget_set_timer_val(SURGEONTarget UNUSED *self,
                                               PyObject *const *args,
                                               Py_ssize_t nargs) {
    if (nargs != (Py_ssize_t)2) {
        PyErr_Format(PyExc_TypeError, "Wrong number of arguments");
        return NULL;
    }
    Py_ssize_t index = PyLong_AsSsize_t(args[0]);
    if ((index == -1 && PyErr_Occurred()) || (index < 0)) {
        PyErr_Format(PyExc_ValueError, "Invalid timer index");
        return NULL;
    }

    unsigned long long tick_val = PyLong_AsUnsignedLongLong(args[1]);
    if (tick_val == -1ULL && PyErr_Occurred()) {
        PyErr_Format(PyExc_ValueError, "Invalid tick value");
        return NULL;
    }

    /* Actually set the timer's tick value */
    set_timer_val(index, (uint64_t)tick_val);
    Py_RETURN_NONE;
}
