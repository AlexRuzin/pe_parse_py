from pe_parse import PEParse

def main():
    filePath = "notepad++.exe"
    print("PE Parser Main")

    try:
        peParser = PEParse(filePath)
    except Exception as e:
        print(f"Exception Caught: {e}")

if __name__ == "__main__":
    main()