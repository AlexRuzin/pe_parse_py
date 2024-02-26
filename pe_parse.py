def log_function_call(func):
    def wrapper(*args, **kwargs):
        print(f"Calling function: {func.__name__} with args {args} kwargs {kwargs}")
        result = func(*args, *kwargs)
        print(f"{func.__name__} return {result}")
        return result
    return wrapper

class PEParse:
    @log_function_call
    def __init__(self, filepath):
        self.filepath = filepath
        print(f'filepath: {self.filepath}')

    @log_function_call
    def read_file(self):
        try:
            with open(self.filepath, 'rb') as file:
                self.raw_bin = file.read()
        except FileNotFoundError:
            print("Error: File not found.")
        except IOError as e:
            print(f"IO Error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
    

if __name__ == "__main__":
    print("PEParser")