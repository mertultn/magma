@echo off
REM ============================================
REM Bu dosya yeni bir GitHub deposu oluşturup
REM mevcut tüm dosyaları oraya yükler.
REM Kullanmadan once USERNAME ve REPONAME
REM degerlerini kendi bilgilerinle guncelle.
REM Ornegin:
REM   set USERNAME=senin-kullanici-adin
REM   set REPONAME=proje-adi
REM ============================================

set USERNAME=KULLANICI_ADIN
set REPONAME=PROJE_ADIN

echo.
echo [1/5] Git init yapiliyor (gerekiyorsa)...
if not exist .git (
    git init
)

echo [2/5] Tum dosyalar ekleniyor...
git add .

echo [3/5] ilk commit olusturuluyor...
git commit -m "Initial commit"

echo [4/5] Ana dal ayarlaniyor...
git branch -M main

echo [5/5] Remote ayarlaniyor ve push ediliyor...
git remote remove origin 2>nul
git remote add origin https://github.com/%USERNAME%/%REPONAME%.git
git push -u origin main

echo.
echo Islemin tamamlandi. Bundan sonra her degisiklik sonrasinda:
echo   git add .
echo   git commit -m "degisiklik mesaji"
echo   git push
echo komutlarini calistirarak repoyu guncelleyebilirsin.
pause
