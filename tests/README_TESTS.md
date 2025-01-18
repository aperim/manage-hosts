# Testing manage_hosts.py in VSCode

Below are guidelines for setting up Visual Studio Code (VSCode) to run test cases against the “manage_hosts.py” script. These steps assume you have a standard Python 3.9+ environment and have cloned or downloaded the repository containing manage_hosts.py and this tests folder.

--------------------------------------------------------------------------------
## 1. Install Python and Required Dependencies

1. Make sure Python 3.9+ is installed on your system.  
2. Create a virtual environment in your project folder (optional but recommended):
   python -m venv venv  
   On Linux/Mac: source venv/bin/activate  
   On Windows: .\venv\Scripts\activate  
3. Install the dependencies in requirements.txt:
   pip install -r requirements.txt  

--------------------------------------------------------------------------------
## 2. Open the Project in VSCode

1. Launch VSCode.  
2. Use “File → Open Folder...” (or “Open...” on macOS) and select the top-level folder of this project (the folder containing “src” and “tests”).  
3. If the Python extension for VSCode is installed, you can select your virtual environment interpreter by clicking on the Python version shown in the bottom-right status bar, then selecting the one in “venv”.

--------------------------------------------------------------------------------
## 3. Configure Testing in VSCode

1. In VSCode, open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P).  
2. Search for “Python: Configure Tests” and select “unittest” as the test framework.  
3. When asked for the test folder, point it to “tests”.  
4. Once configured, VSCode should automatically discover and list the tests under the “Testing” pane (beaker icon on the left sidebar).

--------------------------------------------------------------------------------
## 4. Running Tests

• From the “Testing” pane in VSCode, you can expand “tests/test_manage_hosts.py” to see the individual test cases.  
• Click the “Run Test” button next to any test to run a single test, or click the “Run All Tests” button to run the whole suite.  
• The test results and any console output appear in VSCode’s “Test” output panel.

--------------------------------------------------------------------------------
## 5. Running Tests from Terminal (Optional)

If you prefer to run tests outside of the VSCode interface:

1. Ensure your virtual environment is active (if using one).  
2. From the project root (where “src” and “tests” reside), run:  
   python -m unittest discover -s tests  

This command automatically locates and runs all test scripts matching “test*.py” in the “tests” folder.

--------------------------------------------------------------------------------
## 6. Tips

• Over time, you may wish to split tests into multiple files for clarity, for example test_filters.py, test_ssh.py, etc. Just ensure they either reside in the “tests” folder or have a matching pattern.  
• By default, any tests that attempt network or filesystem operations should be mocked or performed in a controlled environment. The sample tests here demonstrate mocking for paramiko’s SSH and local file reading.  
• If you’d like to switch to pytest instead of unittest, simply install pytest into your environment and configure the VSCode Python extension to use pytest.
