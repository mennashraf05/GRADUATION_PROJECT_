import smtplib

try:
    print("Connecting...")
    server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
    print("Connected to server")
    
    server.ehlo()
    print("EHLO OK")
    
    server.starttls()
    print("STARTTLS OK")
    
    server.ehlo()
    print("EHLO after TLS OK")

    server.quit()
    print("DONE — SMTP connection works!")
except Exception as e:
    print("ERROR:", e)
