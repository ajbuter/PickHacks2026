import torchaudio
if not hasattr(torchaudio, "list_audio_backends"):
    torchaudio.list_audio_backends = lambda: ["soundfile"] 
    
import torch
import speechbrain
import os
import numpy as np
import sounddevice as sd
from speechbrain.pretrained import SpeakerRecognition

model = SpeakerRecognition.from_hparams(
    source="speechbrain/spkrec-ecapa-voxceleb",
    savedir=os.path.expanduser("~/Documents/PickHacks26/pretrained_models/spkrec")
    )

DATABASE_PATH = "voices"
voice_db = {}

def build_voice_database():
    if not os.path.exists(DATABASE_PATH):
        os.makedirs(DATABASE_PATH)
        print(f"Created {DATABASE_PATH} folder. Add .wav files there first!")
        return

    for file in os.listdir(DATABASE_PATH):
        if file.endswith(".wav"):
            user_id = file.replace(".wav", "")
            audio_path = os.path.join(DATABASE_PATH, file)
            signal, fs = torchaudio.load(audio_path)
            embedding = model.encode_batch(signal)
            voice_db[user_id] = embedding.detach().cpu().numpy()
    print(f"Database built with {len(voice_db)} users.")

def record_and_recognize(duration=5, sample_rate=16000, threshold=0.6):
    print(f"\n>>> Recording for {duration} seconds... Speak now!")
    
    recording = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1)
    sd.wait() 
    
    signal = torch.from_numpy(recording).float().reshape(1, -1)
    
    test_embedding = model.encode_batch(signal).detach().cpu().numpy()

    best_match = None
    best_score = -1

    for user_id, db_embedding in voice_db.items():
        similarity = np.dot(test_embedding.flatten(), db_embedding.flatten()) / (
            np.linalg.norm(test_embedding) * np.linalg.norm(db_embedding)
        )

        if similarity > best_score:
            best_score = similarity
            best_match = user_id

    if best_score >= threshold:
        return {"match": True, "user_id": best_match, "confidence": float(best_score)}
    else:
        return {"match": False, "user_id": "Unknown", "confidence": float(best_score)}

build_voice_database()

if voice_db:
    result = record_and_recognize()
    
    print("-" * 30)
    if result["match"]:
        print(f"ACCESS GRANTED: Welcome back, {result['user_id']}!")
    else:
        print("ACCESS DENIED: Voice not recognized.")
    print(f"Confidence Score: {result['confidence']:.4f}")