!define productName "Smartlaunch Fix"
!define baseName "smlfix"
!define productVersion "0.8.3.0"

Name "Smartlaunch Fix Service Setup"
OutFile "${baseName}_${productVersion}.exe"
InstallDir "$WINDIR\system32"

section
	SetOutPath $INSTDIR
	# Check if smlfix was already installed.
	IfFileExists "$INSTDIR\${baseName}.exe" 0 install
	MessageBox MB_YESNO "${productName} was already installed. Do you want to uninstall it?" IDNO cancel 
	ExecWait '$INSTDIR\${baseName}.exe -u'
	Sleep 2000
	Delete '$INSTDIR\${baseName}.exe'
	Delete '$INSTDIR\${baseName}.dll'
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "Userinit" "$WINDIR\system32\userinit.exe,"
	MessageBox MB_OK "The old ${productName} was UNINSTALLED!"

	install:
	MessageBox MB_YESNO "Do you want to INSTALL ${productName} now?" IDNO cancel 
	File ${baseName}.exe
	File ${baseName}.dll
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "Userinit" "$INSTDIR\${baseName}.exe -efw -a reboot2,"
	MessageBox MB_YESNO "Do you want to run ${productName} now?" IDNO finish
	ExecWait "$INSTDIR\${baseName}.exe -w -a reboot2"
	MessageBox MB_OK "Smartlaunch client is now protected!"
	goto finish

	cancel:
	MessageBox MB_OK "The ${productName} (un)installation was CANCELLED!"
	goto done

	finish:
	MessageBox MB_OK "The ${productName} (un)installation was FINISHED!"

	done:
sectionEnd

