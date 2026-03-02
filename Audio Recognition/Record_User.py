import sounddevice as sd
from scipy.io.wavfile import write
import os

def enroll_user(user_name):
    fs = 16000  
    duration = 10 
    folder = "voices"
    
    if not os.path.exists(folder):
        os.makedirs(folder)

    print(f"--- RECORDING FOR {user_name} ---")
    print(f"Speak clearly into the mic for {duration} seconds...")
    
    recording = sd.rec(int(duration * fs), samplerate=fs, channels=1)
    sd.wait() 

    file_path = os.path.join(folder, f"{user_name}.wav")
    write(file_path, fs, recording)
    
    print(f"Success! Saved to {file_path}")
    print("Now run your Audio_Recognition_System.py script.")

if __name__ == "__main__":
    name = input("Enter your name: ").strip().lower()
    enroll_user(name)