NAME=ft_traceroute
SRC_DIR=Source
SRC_FILES=main.c
OBJ_DIR=Obj
OBJ_FILES=$(SRC_FILES:.c=.o)
INCLUDE_DIRS=Source

CC=gcc
C_FLAGS=$(addprefix -I, $(INCLUDE_DIRS)) #-Wall -Wextra -Werror

all: $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c Source/ft_traceroute.h Makefile
	@mkdir -p $(@D)
	$(CC) $(C_FLAGS) -c $< -o $@

$(NAME): $(addprefix $(OBJ_DIR)/, $(OBJ_FILES))
	$(CC) $(C_FLAGS) $(addprefix $(OBJ_DIR)/, $(OBJ_FILES)) $(addprefix -L, $(LIB_DIRS)) $(addprefix -l, $(LIBS)) -o $(NAME)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
