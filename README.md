# Motivation
The main goal behind this project is to provide a small proof of concept about the abstractability of FIDO tokens on Linux. The current situation for the Linux operating systems is that every application basically has access to any FIDO token connected to the system and can request arbitrary attestations. On other Windows, Android, Mac and iOS the operating system itself handles interaction with those tokens. Due to security reasons this centralized access approach would be desirable for Linux as well. More details on why and a bit on how can be read up in [this blog](https://alfioemanuele.io/dev/2024/01/31/a-vision-for-passkeys-on-the-linux-desktop.html) post by Alfie Fresta. His [xdg-credentials-portal](https://github.com/AlfioEmanueleFresta/xdg-credentials-portal) proposal was an inspiration for this project as well.  

# Setup
This repository contains all source code (except the code needed to build Firefox with it, which can be found [here](https://github.com/aurarius1/FidoFirefox-MasterProjekt?tab=readme-ov-file#fidomp_firefox)). 

To test with the included python client you need to clone the  [webauthn-test-server by Jakob Heher](https://extgit.iaik.tugraz.at/jheher/webauthn-test-server/-/tree/main). If you'd like to try it with Firefox you can either also test it using this server, or you can go to [webauthn.io](https://webauthn.io) and test it there as well. Be warned: if you test it with webauthn.io it will prompt for a token verification upon page load, in the baseline Firefox it does not do it, so it is due to my modifications to Firefox itself. I narrowed it down to the GetAssertion method, were Firefox probably has a check in their authenticator-rs library that I do not have, so if you use webauthn.io please just close the first popup requesting access to your tokens - it is to be ignored.

## Build Dependencies
- [sdbus-cpp v1.5.0](https://github.com/Kistler-Group/sdbus-cpp/releases/tag/v1.5.0) - please follow the install instructions and also install the xml generation tool
- Cargo & Rust - v1.76.0
- kdialog v21.12.3

The remaining dependencies to build (like the xdg-credentials-portal/libwebauthn from this project) will be cloned by the install script contained in the repository. The install script will first call the build script, building the server executable (and therefore cloning the xdg-credentials-portal and all the other automatable dependencies) and then create all the needed files.

If you are not interested in what exactly is implemented and how it was done, skip to [usage](#usage).

# How it works
The main achievement of this project was the transfer of the ownership of a FIDO token (in the case of this library this only refers to tokens by Yubico, as the UDEV rules is only implement for this specific vendor id) to a specific user, that has no login and therefore can only be used by another user that has root privileges. The [udev rule](library/91-claim-fido.rules) is set to "look" for any hidraw device with vendor id "1050" and then transfers ownership of the device to the fido user. This then only allows this user to access the token (tested with a YubiKey 5). 

The next challenge to tackle is now how can we talk to this token, if only this user can access it? To solve this problem we can run an application that exposes the capabilities of a Fido token via an API. This API should be accessible to any user - though in the long run it would probably be wise to not only have this centralized access but also some access control in place. Luckily DBUS also exposes some functions to check the binary of the calling service, though this is not part of this project anymore. 

Now about the implementation of the DBUS server. The xdg-credentials-portal repository provides a Rust library (libwebauthn) to interact with any Fido token, to save myself some trouble I decided to use this library to interact with the token. This also meant I needed to write the DBUS server in Rust, though as I am not very familiar with Rust I decided to just build a little "bridge" between my C++ DBUS server (this server was mostly autogenerated by the sdbus-cpp xml generation tool) and the webauthn library. The main specification of the DBUS interface can be seen in [org.mp.fido.xml](code/org.mp.fido.xml). It contains all the necessary arguments to successfully create a credential and get an assertion. Those two (MakeCredential and GetAssertion) are also currently the only supported methods by this project (as said in the beginning, this is more or less a proof of concept).

I won't go into every implementational detail but here are the key aspects: 

The DBUS server spawns the UI elements to signal token interaction (allowing access to tokens, providing the pin etc.). This is the most crucial part, as this server runs under the fido user, only this user is able to do that and the UI elements therefore come from a "trusted" source. Here would also be room for improvement as using the DBUS utilities mentioned before, would allow us to display name of the caller binary and probably other information about the caller (depending of course on what DBUS provides here).

The Rust "bridge" exposes a struct where all of the request data is stored and then repackages the data to the format the webauthn library expects. A word of warning here: the passing of extensions is theoretically supported for this library, but in my testing the server crashed when the extensions were passed in CBOR format (my research and limited Rust knowledged there showed, that the serialization of the Vec\<u8\> is not working in that case, as it literally gets serialized as an array of integers and not as a map as it would be expected - the issue will be reported to the xdg-credentials-repository).

Certainly there is also development-wise a lot of room for improvement (probably error handling, timeout of DBUS calls etc.), but as a matter of fact, it is working and can request assertions / create credentials. 


# Usage
Basically after you've run the install script you should log out and then log in again (to really apply the new udev rule and everything) and then you could start the webauthn-test-server and the [client](code/pyclient/client.py). If you run the client for the first time after starting the webauthn-test-server you need to run it with 

```
python3 client.py --make-credential
```

after that omitting the make-credential flag is fine (as the credential already exists).

If you want to test it using Firefox you need to follow the setup instruction [here](https://github.com/aurarius1/FidoFirefox-MasterProjekt?tab=readme-ov-file#fidomp_firefox). There is an additional check or something that prevents webauthn.io from prompting user interaction for a token interaction, my version does not have this check, so you can ignore the first token interaction request (or do it, it shouldn't really matter).

# C++ client 
There is also a simple client library for C++ (that is used for Firefox as well), located [here](code/client/). For reasons of compatability with Firefox it does not use sdbus-cpp (as it requires exceptions to be enabled and Firefox, by default, has exceptions disabled). Though, if you are interested in a client using sdbus-cpp you could use the generated client proxy (client/fido-client-glue.h) as a starting point.

# Development
If you want to extend this, or base your work on this by running the install script you basically have everything you need. If you want to run the DBUS server binary by hand, be sure to disable and stop the systemd service first (as DBUS only allows one instance of this server running at a time) and run 

```
sudo -u fido path/to/executable
```

The install script should have cloned all the other dependencies into a path inside this repository. If you make changes to the libwebauthn-bridge, you need to copy that to the /usr/lib path (see installation script for full path) or adapt the Makefile to link your new version to the server executable.

# Uninstall
The uninstall script basically removes all the installed files, stops the systemd service and removes the fido user, restoring your system to a point before running the install script. After that you can delete all the dependencies manually installed and remove this repository.