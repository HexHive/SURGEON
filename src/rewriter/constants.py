# Constants used in the rewriter

# Number of bytes in 16MB (unconditonal)/1MB (conditional) -- the maximum reach of a branch instruction
BRANCH_MAXDIST = 16 * 1024 * 1024
COND_BRANCH_MAXDIST = 1024 * 1024
