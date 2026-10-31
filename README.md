# Piranha-Extension
This open-source extension allows users to block websites, report suspicious websites, and sync approved community reports to a blacklist.
This project was developed by seniors in the computer science department at Tennessee State University for their senior project.
Below you will find the appropriate steps to begin running the extension and its backend locally on your computer.

#Setting up/Testing the Backend

//
To set up the backend of the extension, perform the following steps:
1. Download or clone this repository to a local directory on your computer.
2. Open the `Backend` folder within a code editor such as VSCode.
3. Create a new terminal in VSCode and change into the Backend folder:
	```powershell
	cd Backend
	```
4. Set your Supabase database connection URL and your VirusTotal API key in the terminal. Replace the placeholder values with your actual information:
	```powershell
	$env:DATABASE_URL = "postgresql://postgres:YOUR_PASSWORD@YOUR_HOST:5432/postgres"
	$env:VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
	```
5. Install the required Python packages and run the backend:
	```powershell
	python -m pip install -r requirements.txt
	python -m uvicorn piranha_backend_:app --reload
	```
6. After running the command, click the local address that is created and add `/docs` at the end. For example: `http://127.0.0.1:8000/docs`.
7. You are now ready to test the backend. The `/api/report` route checks each submitted URL against VirusTotal and only stores it if at least one vendor flags it as malicious; `/api/blocked-sites` returns approved community reports for the extension.
//

#Setting up/Testing the Frontend

//
To set up the extension in your Chrome browser, perform the following steps:
1. Open a second terminal in VSCode and change into the `Frontend` folder:
	```powershell
	cd Frontend
	```
2. Install the frontend dependencies and build the Chrome extension:
	```powershell
	npm install
	npm run build
	```
3. Go to Google Chrome and enter `chrome://extensions/` into the URL or click the puzzle piece on the top-right toolbar.
4. Toggle the switch to turn Developer mode on in the top right of the page.
5. Select Load unpacked on the left.
6. Select the `Frontend/dist` directory created by the build command.
7. Remember to enable the extension by toggling its switch.
8. You should be ready to use the extension! Keep the backend terminal running while testing report submission and community blacklist synchronization.

After changing frontend source files, run `npm run build` again and click the reload icon for the extension on the `chrome://extensions/` page.
//

#Additional Links for Access:
//
Since this is a full stack project, there are a few different interconnected parts which flow into each other. Additionally, it's helpful to have links to tools, resources, and documentation for development. Below are some great resources if you need help.


Frontend:
Chrome Extensions Docs: https://developer.chrome.com/docs/extensions


Backend:
FastAPI Documentation: https://fastapi.tiangolo.com/

SQLAlchemy Documentation: https://docs.sqlalchemy.org/en/20/

Pydantic Documentation: https://docs.pydantic.dev/


Database:
Supabase (PostgreSQL Database): https://supabase.com/docs
//

Note: This extension uses code from a GitHub repository by IAmTomShaw. Here is the link to the repo -> https://github.com/IAmTomShaw/Website-Blocker-Chrome-Extension.git.
Please check out the original code as well and its tutorial on YouTube. Thanks!


