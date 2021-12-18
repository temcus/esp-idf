set(srcs
	"src/sif.c"
)

set(include_dirs "include")

IDF_COMPONENT_REGISTER(
	SRCS "${srcs}"
	INCLUDE_DIRS "${include_dirs}"
	PRIV_REQUIRES app_update esp-detools log spi_flash
)

