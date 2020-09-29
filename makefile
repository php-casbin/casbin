# Define C/C++ compiler variables
CXX := g++

EXTENSION_DIR    =    $(shell php-config --extension-dir)
INI_DIR 		 =    $(shell php -i | grep 'additional .ini files' | awk '{print $$NF}')

# Define compiler flags
OBJ_FLAG := -c -fPIC
FILE_FLAG := -o
STD_FLAG := -std=c++11

# Define archive flags
SO_FLAG := -shared -o
SO_NAME := casbin.so
INI_NAME := casbin.ini

# Define directory variables
SRC_DIR := casbin
OBJ_DIR := obj
LIB_DIR := so

# Define extension variables
SRC_EXT := cpp
OBJ_EXT := o
LIB_EXT := a
INC_EXT := h

# Define make directory command variable
MKDIR_P := mkdir -p
CP      := cp -f

# Get source cpp files
SRC_FILES := $(shell find $(SRC_DIR) -type f -name *.$(SRC_EXT))
INC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAG_DIRS := $(addprefix -I /, $(INC_DIRS))
OBJ_DIRS := $(addprefix $(OBJ_DIR)/, $(INC_DIRS))

.PHONY: object
object:
	$(foreach OBJ_DIR, $(OBJ_DIRS),\
		$(MKDIR_P) $(OBJ_DIR);\
	)
	$(foreach SRC_FILE, $(SRC_FILES),\
		$(CXX) $(STD_FLAG) $(OBJ_FLAG) $(FILE_FLAG) $(SRC_FILE:$(SRC_DIR)/%.$(SRC_EXT)=$(OBJ_DIR)/$(SRC_DIR)/%.$(OBJ_EXT)) $(SRC_FILE);\
	)

#Get object files
OBJ_FILES := $(shell find $(OBJ_DIR) -type f -name *.$(OBJ_EXT))

.PHONY: library
library:
	$(MKDIR_P) $(LIB_DIR)
	$(CXX) $(SO_FLAG) $(SO_NAME) $(OBJ_FILES) -lphpcpp
	mv $(SO_NAME) $(LIB_DIR)/$(SO_NAME)

.PHONY: clean
clean:
	rm -r $(OBJ_DIR)

.PHONY: install
install:
	${CP} ${LIB_DIR}/${SO_NAME} ${EXTENSION_DIR}
	${CP} ${INI_NAME} ${INI_DIR}
