# backend/wsgi.py
from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run()  # Tylko dla celów developerskich