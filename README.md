# Piranha-Extension
This open-source extension will allow users to block websites and report them to a community blacklist.
This project was developed by seniors in the computer science department at Tennessee State University for their senior project.
Below you will find the appropriate steps to begin running the extension and its backend locally on your computer. This current
architecture will change as soon as we designate a cloud server for the python backend code to run on. For testing purposes, the below 
advice should help you to get started. At the current moment, we do not have the frontend connected to the backend just yet. 

#Setting up/Testing the Backend
//
To setup the backend of the extension, perform the following steps: 
1. Download the piranha_backend_.py file from within the Backend folder. (You can also just download the whole repository if that makes it easier.)
2. Open the Python file within a code editor such as VSCode.
3. Create a new terminal in VSCode and run the command "python -m uvicorn PiranhaPythonBackend:app --reload"
   Note: Make sure you are in the same directory as the file or you may get an error. To change directories, type in cd into the terminal window followed by
   the folder you are trying to access which contains the python file.
4. After, running the command, click on the local IP address that is created and make sure to add "/docs" at the end.
5. You are now ready to test the backend! From your web browser, you can send test JSON data to the python script. Just click on the "/api/report" tab and then
   the "Try it out" button. You should be given a JSON template which you can play around with and send to the python script. By testing this feature, you can see
   how data is passed from the frontend to the backend, how the Python backend responds with HTTP status codes, and how the data is populated on the database side. 
//

#Setting up/Testing the Frontend
//
To setup the extension in your chrome browser, perform the following steps:
1. Download or clone the code from this repository to a local directory on your computer. (*For this portion, you will only need the code from the "Frontend" folder of
   the repository.) 
3. Go to Google Chrome and enter "chrome://extensions/" into the URL or click the puzzle piece on the top-right toolbar.
4. Toggle the switch to turn developer mode on in the top right of the page.
5. Select "Load Unpacked" on the left.
6. Select the directory you saved/cloned the repository to.
7. Remember to enable the extension by toggle the switch 
8. You should be ready to use the extension! Happy Reporting!
//

#Additional Links for Access: 
//
Since this is a full stack project, their are a few different interconnected parts which flow into each other. Additionally, it's helpful to have links to any tools/resources/and or 
documentation we have for development. Below are some great resources if you need help.

Frontend: 
Chrome Extensions Docs: https://developer.chrome.com/docs/extensions

Backend: 
FastAPI Documentation: https://fastapi.tiangolo.com/
SQLAlchemy Documentation: https://docs.sqlalchemy.org/en/20/
Pydantic Documentation: https://pydantic.dev/docs/validation/latest/get-started/

Database: 
Supabase (PostgreSQL Database): https://supabase.com/docs
//


Note: This extension uses code from the a GitHub Repo by IAmTomShaw. Here is the link to the repo -> https://github.com/IAmTomShaw/Website-Blocker-Chrome-Extension.git. 
Please check out the original code as well and his tutorial on youtube (https://www.youtube.com/watch?v=wZcU07zfMSk). Thanks!


