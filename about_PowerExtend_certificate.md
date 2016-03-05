#### Table Of Content

- [What is a Certificate](#what-is-a-certificate)
   - [How it works](#how-it-works)
      - [How is this related to certificates](#how-is-this-related-to-certificates)
   - [Fields in a certificate](#fields-in-a-certificate)
      - [Name](#name)
      - [Capability](#capability)
      - [Specification](#specification)
   - [Creating a self-signed certificate](#creating-a-self-signed-certificate)
- [The whole certificate creation workflow](#the-whole-certificate-creation-workflow)
   - [TestCo Root CA](#testco-root-ca)
   - [TestCo Intermediate CA](#testco-intermediate-ca)
      - [Request](#request)
      - [Approve](#approve)
      - [Install](#install)
   - [End entities](#end-entities)
- [Profit](#profit)
   - [Profit 1](#profit-1)
   - [Profit 2](#profit-2)

------------------------------------------------------------------------------------

# What is a Certificate

A **Certificate** is like an identity card for the digital world. If properly implemented,
 it can be very useful in ensuring that a piece of data comes from a certain author.

## How it works

The whole infrastructure sits on top of [**asymmetric encryption**](https://en.wikipedia.org/wiki/Public-key_cryptography):

Say John encrypts his message with a password. Jane must know the password in order to decrypt
 John's message. This is bad because John must then tell Jane his password somehow.

Comes asymmetric encryption: John can encrypt his message with password `'A'`. Jane decrypts
 the message with password `'B'`. The maths behind ensures that there is only one `'A'` to `'B'`
  and vice verse. Also, Jane won't be able to work out what `'A'` is by knowing `'B'` and the
   message (encrypted or otherwise).

This helpful property in asymmetric encryption can be used for digital signing. Here's how it works:

1. John encrypts the word `'banana'` with password `'A'`. The result is `'b83nbl1='`;

2. John writes on a bulletin board: *My public password is `'B'`*. If you use that password to decrypt `'b83nbl1='`, you will get back `'banana'`;

3. Jane saw the post and ran the maths. Sure enough, John's words were true. Since there is only one pair of `'A'` and `'B'`, John must know password `'A'` in order to encrypt the message. Assuming that nobody else knows password `'A'`, she knows that the poster must be John.

### How is this related to certificates

Certificates are all about signing. You begin by trusting a **root certificate authority (CA)**. You got to trust someone right? To do that, you save that CA's name and password `'B'` on your computer.

Now a requestor (we call a *'subject'*) will ask the CA (the *'issuer'*) to sign a message (the *'certificate'*). In essense, the message says who the *subject* is, and what purpose was the *certificate* for (e.g. be the SSL certificate for a website). The *issuer* will (after getting paid, of course) sign the message and return it to the *subject*.



## Fields in a certificate

There are many fields in a certificate. We can put them into 3 broad categories:

- Name
- Capability
- Specification

### Name

This is mainly about the issuer and the subject (recipient of the certificate).

Think about your college degree: it is issued by your school (the issuer) to you (subject). In each case, there are a lot of information that can be said.

Use the **`New-CertificateName`** command to create a naming object.

Note that certain fields can only support a single value (such as your DNS name, like `'www.fabrikom.com'`). This creates a problem when you want a certificate that can work for many domains (e.g. `'www.fabrikom.com'`, `'mail.fabrikom.com'`). You can use an alternate name in this case (SAN).

Most if not all commercial certification authorities charge a lot extra for SAN names. (So as to encourage you to buy more individual certificates from them?)


### Capability

Here we are concerned with the purpose of the certificate.

The easiest way is to create an all-capable certificate (if there is such a thing). However, conventional wisdom dictates that we create separate certificates for different purposes, so that you don't *'lose it all'* when a private key gets stolen.

The **`Add-CertificateCapability`** command offers templates for different purpose certificates. You can also create custom capabilities too.

Commercial certificates are sold on a per-purpose basis. For instance, website SSL certificates are charged less than code signing certificates. Is it because there are less codesign than webmasters customers? Kind of weird when running an executable is more risky than visiting a website.


### Specification

The last part is all about the maths: What cryptographic engine to use? What algorithm? How long should the keys be?





## Creating a self-signed certificate

This is a special case where the issuer is the subject.

All root CA are self-signed certificates. It's like a self-proclaimed king. Since these companies are *'well-established'*, browsers and Windows install them onto your system by default. They then start issuing more certificates to those who must pay.

The truth is anyone can create a self-signed certificate. To try, check out the **`New-RootCertificate`** command.

Of course, your certificate is not included by major browsers and operating systems by default. So people will need to install your certificate in order for things to work.


------------------------------------------------------------------------------------


# The whole certificate creation workflow

We're going to build a certificate hirarchy:

```
[-]-- TestCo Root CA
      |--[-] TestCo Intermediate CA
             |-[-] TestCo CodeSign
             |-[-] TestCo.com
             |-[-] john@testco.com
```

All these makes more sense if you fire up certificate manager (<kbd>run</kbd> > <kbd>certmgr.msc</kbd>):

* **TestCo Root CA**

  will live in the **Trusted Root Certificate Authority** store. Just for being lazy, we won't restrict what it can do. It is a self-signed certificate, which means the issuer and subject are the same person (the self-proclaimed king).

* **TestCo Intermediate CA**

  will live in the **Intermediate Certificate Authority** store. This certificate is requested by **TestCo Intermediate CA**, and approved by **TestCo Root CA**. We're going to make it a little more restrictive in what it can do.

* **TestCo CodeSign**

  is issued for the purpose of code signing only. It is issued by **TestCo Intermediate CA**. **TestCo CodeSign** will not be issue any more certificates down the line. It is an *'end-entity'*.

* **TestCo.com**

  is a SSL certificate that will be installed on a webserver. It is issued by **TestCo Intermediate CA**. **TestCo.com** is also an 'end-entity'.

* **john@testco.com**

  is issued to John for him to encrypt documents and proving his identity online. It is issued by **TestCo Intermediate CA**. It is an 'end-entity' too.

The whole tree structure makes sense if you ever lose the private key to **TestCo Intermediate CA**. **TestCo Root CA** can then sign a message that says **TestCo Intermediate CA** has been stolen. This is called revocation.




## TestCo Root CA

Let's start by creating a self-signed certificate:

```PowerShell
$passwd = ConvertTo-SecureString -String 'casecret' -AsPlainText -Force
$issuer = New-CertificateName -CommonName 'TestCo Root CA' -FriendlyName 'TestCo Root' -Company 'TestCo Inc.' -Department @('(c) 2008 TestCo Inc. - For authorized use only', 'TestCo Trust Network') -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -PolicyUrl @('http://cert.testco.com/policy', 'http://cert.testco.com/intermediate') -PolicyStatement 'Limited liability. Read the *Legal Limitations* section of the TestCo Certification Authority Policy available at http://cert.testco.com/policy'
$caCapability = Add-CertificateCapability -Capability Template -Purpose RootCA
New-RootCertificate -OutFile .\testroot.pfx -Name $issuer -Capability $caCapability -Password $passwd -Verbose
$pfx = Import-Certificate -Path .\testroot.pfx -Password $passwd -KeyStorageFlags Exportable
$pfx | ConvertFrom-PfxCertificate -OutFile testroot.crt -OutputFormat PEM
Install-Certificate -Path .\testroot.crt -StoreLocation CurrentUser -StoreName Root -Exportable -Password $passwd
```

#### Description

First we create a password to protect our certificate. My password is `'casecret'`. I store in a variable called `$passwd`.

Next we create an object to hold the subject information. There are a lot of fields, but the `CommonName` field is essential. The variable to hold subject information is called `$issuer`.

Then we make the certificate authority (CA) certificate using the **`New-RootCertificate`** command. Remember that a self-signed root certificate means the issuer and subject are the same person, so there is only one `Name` parameter. Also note that I'm creating an all-purpose certificate, but you'll probably want to further restrict its capability in real life.

The command outputs a certificate file `testroot.pfx`. Note that the private key is embeded in the **PFX** certificate file, and is protected by the password I first set. So **keep the PFX file real safe!**

At this point, you can click on the `testroot.pfx` file in Windows Explorer and import it, but let's be hardcore and do it all from the command line.

I start off by importing my CA certificate back from the file `testroot.pfx`, storing it in a variable called `$pfx`. Next, I use the **`ConvertFrom-PfxCertificate`** command to export the certificate as a file again. This time it is in the **PEM** format, and I did not export the private key.

To install the CA certificate, use the **`Install-Certificate`** command. You do not want to distribute your PFX file, since it contains your private key. Instead, distribute the file `testroot.crt`.

I'm installing the certificate for myself only. If you want to install the certificate for all users on the PC, you'll need to use the `LocalMachine` store and run things from an elevated terminal.


## TestCo Intermediate CA

### Request

So we're now a self-proclaimed king. Let's create a subordinate certificate!

```PowerShell
$subca = New-CertificateName -CommonName 'TestCo Intermediate CA' -FriendlyName 'TestCo Intermediate' -Company 'TestCo Inc.' -Department @('(c) 2008 TestCo Inc. - For authorized use only', 'TestCo Trust Network') -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -PolicyUrl @('http://cert.testco.com/policy', 'http://cert.testco.com/intermediate') -PolicyStatement 'Limited liability. Read the *Legal Limitations* section of the TestCo Certification Authority Policy available at http://cert.testco.com/policy'
$subcaCapability = Add-CertificateCapability -Capability Template -Purpose CommonCA
$priv = New-CertificatePrivateKey
Export-CertificatePrivateKey -PrivateKey $priv -OutFile .\testsubca.key
$request = New-CertificateRequest -Name $subca -Issuer $issuer -PrivateKey $priv -Capability $subcaCapability
$request | Export-CertificateRequest -OutFile .\testsubca.req -Encoding Base64Request
$priv.Delete()
```

#### Description

First we create the subject. I made sure that it is a different name from the issuer.

Then we build the certificate capability in a variable called `$subcaCapability`.

Creating a private key is easily done with the **`New-CertificatePrivateKey`** command. I go further to export the key to a file. Keep it safe!

Time to make the certificate request. To do that, use the 'New-CertificateRequest' command. Feed in the subject, issuer, and capability, plus a few extras. Note that your private key is used to sign the certificate request, but is not embedded in the request itself. Therefore, anyone who gets the request certificate file will NOT know your private key.

I now export the request to a certificate file `testsubca.req`. This file is already a certificate (abit unsigned by the issuer). If you change the extension to `.crt`, you can open it up with Windows Explorer.

The last statement `$priv.Delete()` deletes the private key from memory. That made me feel so safe.

Now let's image me passing that file to a certificate authority through email.



### Approve

Let me be the certificate authority now. I have received the request file `testsubca.req` and needs to approve it.

```PowerShell
$request = Import-CertificateRequest -FilePath .\testsubca.req -Encoding Base64Request
$signCert = Import-Certificate -Path .\testroot.pfx -Password (ConvertTo-SecureString -String 'casecret' -AsPlainText -Force)
$approvedRequest = Approve-CertificateRequest -Signer $signCert -Request $request
$approvedRequest | Export-CertificateRequest .\testsubca.crt -Encoding Base64Cert -Force
```

#### Description

We read in the certificate request file in a variable called `$request`.

I now approve of the request by signing it with my self-signed certificate authority certificate (`testroot.pfx`). First I have to import it in. I store my certificate in a variable called `$signCert`.

Signing is done with the **`Approve-CertificateRequest`** command. Plug in the request and signer certificates and we're done.

The last line exports the approved certificate to a file (`testsubca.crt`). At this point the subordinate certificate is signed and valid. Open it up on Windows Explorer and see what I mean!

I now ships it back to the requesting subject.



### Install

Now back to the subject. I have received the approved certificate file (`testsubca.crt`).

```PowerShell
$passwd = ConvertTo-SecureString -String 'subcasecret' -AsPlainText -Force
ConvertTo-PfxCertificate -CertFilePath .\testsubca.crt -PrivateKeyFilePath .\testsubca.key -PrivateKeyPassword $passwd -OutFile .\testsubca.pfx -Password $passwd
Install-Certificate -Path .\testsubca.pfx -StoreLocation CurrentUser -StoreName CertificateAuthority -Password $passwd
```

Pretty simple. Merge the approved certificate and your private key into a PFX file (`testsubca.pfx`). Then install onto your `Intermediate Certificate Authorities` store.

Note that this time I have imported the certificate into the store with the private key. You can see the result by firing up <kbd>certmgr.msc</kbd> > <kbd>Personal</kbd> > <kbd>Certificates</kbd>.

Also I have used a new password `'subcasecret'` for this intermediate CA. Another layer of safety!



## End entities

```PowerShell
$entities = @(
    @{
        'Name' = New-CertificateName -CommonName 'TestCo Software' -FriendlyName 'TestCo Software' -Company 'TestCo Inc.' -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -AlternateEmail 'software@testco.com' -AlternateUPN 'software@testco.com'
        'Capability' = Add-CertificateCapability -Capability Template -Purpose CodeSign
        'FileName' = 'testcoder'
        'Store' = 'My'
        'Password' = 'codersecret'
    },
    @{
        'Name' = New-CertificateName -CommonName 'www.testco.com' -FriendlyName 'TestCo Web' -Email 'postmaster@testco.com' -Company 'TestCo Inc.' -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -AlternateDNS @('www.testco.com', 'testco.com')
        'Capability' = Add-CertificateCapability -Capability Template -Purpose WebServer
        'FileName' = 'testweb'
        'Store' = 'My'
        'Password' = 'websecret'
    },
    @{
        'Name' = New-CertificateName -CommonName 'john@testco.com' -FriendlyName 'John Smith' -GivenName John -Initials JS -SurName Smith -Title Mr. -Company 'TestCo Inc.' -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -AlternateEmail 'john@testco.com' -AlternateUPN 'software@testco.com'
        'Capability' = Add-CertificateCapability -Capability Template -Purpose User
        'FileName' = 'testuser'
        'Store' = 'My'
        'Password' = 'usersecret'
    }
)
$subca = New-CertificateName -CommonName 'TestCo Intermediate CA' -FriendlyName 'TestCo Intermediate' -Company 'TestCo Inc.' -Department @('(c) 2008 TestCo Inc. - For authorized use only', 'TestCo Trust Network') -Locality 'Cape Town' -State 'Western Cape' -Street 'Birch Ave' -Country ZA -PolicyUrl @('http://cert.testco.com/policy', 'http://cert.testco.com/intermediate') -PolicyStatement 'Limited liability. Read the *Legal Limitations* section of the TestCo Certification Authority Policy available at http://cert.testco.com/policy'
$signCert = Import-Certificate -Path .\testsubca.pfx -Password (ConvertTo-SecureString -String 'subcasecret' -AsPlainText -Force)
$entities | ForEach-Object {
    $priv = New-CertificatePrivateKey
    Export-CertificatePrivateKey -PrivateKey $priv -OutFile "$($_.FileName).key"
    $request = New-CertificateRequest -Name $_.Name -Issuer $subca -PrivateKey $priv -Capability $_.Capability -AlternativeName
    $request | Export-CertificateRequest -OutFile "$($_.FileName).req" -Encoding Base64Request
    $approvedRequest = Approve-CertificateRequest -Signer $signCert -Request $request
    $approvedRequest | Export-CertificateRequest -OutFile "$($_.FileName).crt" -Encoding Base64Cert
    $passwd = ConvertTo-SecureString -String $_.Password -AsPlainText -Force
    ConvertTo-PfxCertificate -CertFilePath "$($_.FileName).crt" -PrivateKeyFilePath "$($_.FileName).key" -PrivateKeyPassword $passwd -OutFile "$($_.FileName).pfx" -Password $passwd
    Install-Certificate -Path "$($_.FileName).pfx" -StoreLocation CurrentUser -StoreName $_.Store -Password $passwd 
    $priv.Delete()
    Write-Host '----------[ done ]----------' -ForegroundColor Blue
}
```

This script will create all three end entity certificates (i.e. `TestCo CodeSign`, `TestCo.com` and `john@testco.com`) for different uses. The first one is a code signing certificate, which can be used to sign executable files and PowerShell scripts.

The second one can be installed on a web server. Then you get SSL capabilities (the `https://` thing).

The last one is a personal certificate. You can encode things with it and protect your emails.

Then script generates a bunch of files. Be sure to secure your `.key` and `.pfx` files.

After you have ran the script, you can see all the certificate in the My store (<kbd>certmgr.msc</kbd>).

------------------------------------------------------------------------------------

# Profit

## Profit 1

I'll not be showing you how to use the web server certificate. Check out the server software documentation for more info.

What I'll show you first is how to protect your messages.

```PowerShell
$cert = dir Cert:\CurrentUser\My | Where { $_.Subject.Contains('CN=john@testco.com') }
Protect-String -String 'mysecret' -Certificate $cert | Unprotect-String -Certificate $cert
```

You should get back `mysecret`. This technique can be used to secure your messages with friends:

```PowerShell
# you give your friend your .crt file. Then he'll type in:
$pubcert = Import-Certificate -Path .\testuser.crt
Protect-String -String 'mysecret' -Certificate $pubcert | Set-Content -Path .\secretmsg.txt
# then he pass the output file 'secretmsg.txt' to you.
# from your end:
$cert = dir Cert:\CurrentUser\My | Where { $_.Subject.Contains('CN=john@testco.com') }
Get-Content .\secretmsg.txt -Encoding Ascii | Unprotect-String -Certificate $cert
```

Of course, asymmetric encryption can't keep up the pace when your data gets too big. To solve that problem, you use regular encryption techniques to protect your data with a password, then encrypt your password with a certificate. The **`Protect-File`** command does just that internally.



## Profit 2

Executable files can also be signed. It doesn't protect you like an antivirus program per se, but gives some assurance as to the author of the file.

To test, let's make a powershell script `tester.ps1`. Just write any dummy code, like `Write-Host hello`

```PowerShell
$cert = dir Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -Certificate $cert -FilePath .\tester.ps1
```

If you right click on the file in Windows Explorer, you can now see the digital signature tab.

The same goes for `.exe`/`.dll` files as well.
