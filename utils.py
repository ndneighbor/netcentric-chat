import os


def get_file_lines(file_path):
    """
    Gets the list of lines in a file
    :param file_path: String
    :return: list | None
    """
    file_lines = []
    try:
        with open(file_path) as file_pointer:
            file_lines = [line.replace('\n', '')
                          for line in file_pointer]
    except IOError:
        pass

    return file_lines


def save_file_lines(file_path, file_lines):
    """
    Saves the list of lines to a file
    :param file_path: String
    :param file_lines: String[]
    :return:
    """
    try:
        with open(file_path, "w") as file_pointer:
            file_pointer.writelines(['%s\n' % line
                                     for line in file_lines])
    except IOError:
        pass


def get_config_from_file(config_file_path):
    """
    Returns a config object given a config file
    :param config_file_path: string
    :return: dict
    """
    if not os.path.exists(config_file_path):
        print("Configuration File does not exist")
        return {}

    chat_config = {}
    for config_line in get_file_lines(config_file_path):
        try:
            config_line_splitted = config_line.split(None, 1)
            config_key = config_line_splitted[0]
            config_value = config_line_splitted[1]
            chat_config[config_key] = config_value
        except IndexError:
            continue

    return chat_config