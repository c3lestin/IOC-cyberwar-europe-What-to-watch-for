# Europe Cyberwar: IoCs to watch for.
The tension about the current war between Russia and Ukraine unfortunately is also affecting the IT Security World.  This Github page is being updated constantly with the IoCs (Indicator of Compromises) as they are being surfaced.

<p>This is purely informative.</p>


<p>
  <br/>
</p>
<h1>Indicator of Compromise (IOCs) </h1>
<p>The following IOCs are being surfaced</p>
<p>
  <br/>
</p>
<h2>
  <strong>HermeticWiper:</strong> A Catastrophic Malware </h2>
<p>This malware mainly target windows devices, <span style="color: rgb(96,96,128);">it uses a known and tested technique similar to the Lazarus Group little difference is that , this Wiper abuses a different driver  ( empntdrv[.]sys), it's way of attack is to corrupt the first 512 byte in the MBRs so the machine physical drives booting process can stop. This malware targets the financial, aviation, and IT services sector. </span>
</p>
<h3>
  <span style="color: rgb(96,96,128);">HermeticWiper IOCs </span>
</h3>
<table>
  <colgroup>
    <col/>
    <col/>
  </colgroup>
  <tbody>
    <tr>
      <td colspan="1">
        <strong>Type</strong>
      </td>
      <td colspan="1">
        <strong>IoC</strong>
      </td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA1</td>
      <td colspan="1">912342f1c840a42f6b74132f8a7c4ffe7d40fb77</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA1</td>
      <td colspan="1">61b25d11392172e587d8da3045812a66c3385451</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-MD5</td>
      <td colspan="1">
        <p>eb845b7a16ed82bd248e395d9852f467</p>
      </td>
    </tr>
    <tr>
      <td colspan="1">FileHash-MD5</td>
      <td colspan="1">a952e288a1ead66490b3275a807f52e5</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-MD5</td>
      <td colspan="1">231b3385ac17e41c5bb1b1fcb59599c4</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-MD5</td>
      <td colspan="1">095a1678021b034903c85dd5acb447ad</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">ca3c4cd3c2edc816c1130e6cac9bdd08f83aef0b8e6f3d09c2172c854fab125f </td>
    </tr>
    <tr>
      <td colspan="1">
        <br/>
      </td>
      <td colspan="1">Win32/KillDisk[.NCV] trojan 6/n </td>
    </tr>
  </tbody>
</table>
<p>
  <br/>
</p>

<h3>CTI links</h3>
<ul style="list-style-type: square;">
  <li>
    <a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia">Ukraine: Disk-wiping Attacks Precede Russian Invasion | Symantec Blogs (security.com)</a>
  </li>
  <li>
    <a href="https://www.avertium.com/blog/cisa-warns-of-renewed-russian-threat-new-activity-seen-in-ukraine">Flash Notice: [New Malware] - CISA Warns of Renewed Russian Threat as New Activity is Seen in Ukraine (avertium.com)</a>
  </li>
    <li>
    <a href="https://socradar.io/what-you-need-to-know-about-russian-cyber-escalation-in-ukraine/">What You Need to Know About Russian Cyber Escalation in Ukraine</a>
  </li>
   <li>
    <a href="https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/">Destructive malware targeting Ukrainian organizations</a>
  </li>
</ul>
<p>
  <br/>
</p>
<h2>
  <strong>Cyclops Blink: </strong>The New Weapon of Cyber-Warfare</h2>
<p>This is a new malware that was reported by the US and UK government that might be actively now being used </p>
<h3>Cyclops IOCs </h3>
<table>
  <colgroup>
    <col/>
    <col/>
  </colgroup>
  <tbody>
    <tr>
      <td>
        <strong>Type</strong>
      </td>
      <td colspan="1">
        <strong>IoC</strong>
      </td>
    </tr>
    <tr>
      <td>IPv4</td>
      <td colspan="1">188.152.254[.]170 <br/>208.81.37[.]50 <br/>70.62.153[.]174 <br/>2.230.110[.]137 <br/>90.63.245[.]175 <br/>212.103.208[.]182 <br/>50.255.126[.]65 <br/>78.134.89[.]167 <br/>81.4.177[.]118 <br/>24.199.247[.]222 <br/>37.99.163[.]162 <br/>37.71.147[.]186 <br/>105.159.248[.]137 <br/>80.155.38[.]210 <br/>217.57.80[.]18 <br/>151.0.169[.]250 <br/>212.202.147[.]10 <br/>212.234.179[.]113 <br/>185.82.169[.]99 <br/>93.51.177[.]66 <br/>80.15.113[.]188 <br/>80.153.75[.]103 <br/>109.192.30[.]125<br/>105[.]159.248.137<br/>100[.]43.220.234<br/>96.80.68[.]193  <br/>109[.]192.30.125<br/>151[.]0.169.250<br/>185[.]82.169.99</td>
    </tr>
    <tr>
      <td>FileHash-MD5</td>
      <td colspan="1">bf24ade7-1a90-54a5-8664-fa993256e66f <br/>50e5c6d8-f1ee-593a-bf2c-b99c8c2d6a10 <br/>512e379a-2b3b-5f97-8dd2-03519971c66f <br/>9d16715a-9e88-5305-8e67-110b4dde6848 <br/>d87d5a66-05df-56c4-9311-6e2af3fde2e8 <br/>a8174e4e-7b98-5c0a-9dff-7e6485ed9adc <br/>a8174e4e-7b98-5c0a-9dff-7e6485ed9adc <br/>
        <br/>
      </td>
    </tr>
    <tr>
      <td>Path</td>
      <td colspan="1">/usr/bin/cpd <br/>/var/tmp/a.tmp <br/>rootfs_cfg </td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">ff17ccd8c96059461710711fcc8372cfea5f0f9eb566ceb6ab709ea871190dc6</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">c082a9117294fa4880d75a2625cf80f63c8bb159b54a7151553969541ac35862</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">0df5734dd0c6c5983c21278f119527f9fdf6ef1d7e808a29754ebc5253e9a8</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA256</td>
      <td colspan="1">4e69bbb61329ace36fbe62f9fb6ca49c37e2e5a5293545c44d155641934e39d1</td>
    </tr>
    <tr>
      <td colspan="1">FileHash-SHA1</td>
      <td colspan="1">4e69bbb61329ace36fbe62f9fb6ca49c37e2e5a5293545c44d155641934e39d1</td>
    </tr>
  </tbody>
</table>
<p>
  <br/>
  <br/>
  <br/>
</p>
<p>
  <br/>
</p>
<h2>
  <strong>Katana:<span> </span>
  </strong>DDoS Attacks to Ukraine</h2>
<p>This is one of the cyber attack being used by russia toward ukraine</p>
<h3>Katana IOCs </h3>
<table>
  <colgroup>
    <col/>
    <col/>
  </colgroup>
  <tbody>
    <tr>
      <td colspan="1">
        <strong>Type</strong>
      </td>
      <td colspan="1">
        <strong>IoC</strong>
      </td>
    </tr>
    <tr>
      <td colspan="1" style="text-align: left;">URL </td>
      <td colspan="1" style="text-align: left;">http://5[.]182[.]211[.]5/rip[.]sh </td>
    </tr>
    <tr>
      <td colspan="1" style="text-align: left;">FileHash-SHA256</td>
      <td colspan="1" style="text-align: left;">978672b911f0b1e529c9cf0bca824d3d3908606d0545a5ebbeb6c4726489a2ed</td>
    </tr>
    <tr>
      <td colspan="1" style="text-align: left;">FileHash-SHA256</td>
      <td colspan="1" style="text-align: left;">82c426d9b8843f279ab9d5d2613ae874d0c359c483658d01e92cc5ac68f6ebcf</td>
    </tr>
    <tr>
      <td colspan="1" style="text-align: left;">FileHash-MD5</td>
      <td colspan="1" style="text-align: left;">db8cc8adc726c3567b639c84ecf41aa5</td>
    </tr>
    <tr>
      <td colspan="1" style="text-align: left;">FileHash-SHA1</td>
      <td colspan="1" style="text-align: left;">7504ac78e531762756e8ca8e94adc71fa2179104 </td>
    </tr>
  </tbody>
</table>

<h3>
  <span style="color: rgb(33,37,41);">(Buhtrap) (CERT-UA#3967)</span>
</h3>
<p class="ql-align-justify" style="text-align: justify;">
  <em>Compromise indicators</em>
</p>
<p class="ql-align-justify" style="text-align: justify;">
  <em>Files:</em>
</p>
<pre class="ql-syntax ql-align-justify">	1b5f0425dd76496e715bfa1aa76d306c    facebook.exe (LightRope)
	42397efeaf1d971896cdc91ca024974d    lsass.exe (LiteManager)
	9297e47fe1b256a8bbcb2b7a20844b2c    svchost.exe (LiteManager)
	42397efeaf1d971896cdc91ca024974d    lsass.exe (LiteManager)
	43a9a42b9a656d1ca39a3337a841ad5d    NTDSDumpEx.exe (NTDSDumpEx)
	c1f47a14a958e2345ba929afa829c7e7    2021-07-30-08-55-07.xlsm
	86926e56e4f6d854161066b5989a350e    output.exe (SourSnack)
	3dcec8f6ba15e801b63b7c21a6b966fb    dnsoption.exe (LightRope_v2)
	86f322fe52829b8b8094d053ed648a65    CDSSyncReporting.exe (dnscat)</pre>
<p>
  <br/>
</p>
<p>
  <br/>
</p>
<p class="ql-align-justify" style="text-align: justify;">
  <em>Network:</em>
</p>
<pre class="ql-syntax ql-align-justify">hxxps://mail.nais-gov[.]org/2021-07-30-08-55-07.xlsm	
	widget.forum-pokemon[.]com
	ns.ns2-dns[.]com
	ns.ns3-dns[.]com
	ns3-dns[.]com
	ns2-dns[.]com
	cs1.wpc-v0cdn[.]org
	wpc-v0cdn[.]org
	ipv6-wpnc[.]net
	alt-2cdn[.]net
	nais-gov[.]org
	nais-gov[.]com
	91[.]240.86.200
	89[.]108.101.61
	45[.]76.85.232
	185[.]162.9.218
	95[.]179.135.36
	91[.]240.86.200:5651<br/>
  <br/>
  
</pre>
<p class="ql-align-justify" style="text-align: justify;">
  <em>Host:</em>
</p>
<pre class="ql-syntax ql-align-justify">        C:\windows\system32\wbem\wmic.exe process where ExecutablePath='C:\\ProgramData\\lsass.exe' delete
	C:\windows\system32\wbem\wmic.exe process where ExecutablePath='C:\\ProgramData\\svchost.exe' delete
	C:\windows\system32\schtasks.exe /delete /tn "Network Security Update" /f
	C:\windows\system32\schtasks.exe /create /sc onstart /tn "Network Security Update" /tr "C:\ProgramData\lsass.exe" /ru SYSTEM
	%PROGRAMDATA%\lsass.exe
	%PROGRAMDATA%\svchost.exe
	%PROGRAMDATA%\config.xml
	%PUBLIC%\output.exe
	%APPDATA%\dnsoption.exe
	%APPDATA%\Microsoft\Windows\CDSSyncReporting.exe</pre>
<p>
  <br/>
</p>

<h2><p>Defense Technique </p></h2>
<p>(SANS) The path to winning is to:</p>
<ul>
  <li>Patch</li>
  <li>Tactical &amp; effective logging strategies</li>
  <li>Outbound traffic control ( outbound &amp; geo-blocking)</li>
  <li>Plan and test for rapid containment</li>
  <li>Implement application control</li>
  <li>Make this a sustainable "steady state"</li>
</ul>
<h2>Tenable available scan policies</h2>
<ul>
  <li>CISA Alerts AA22-011A and AA22-047A</li>
</ul
<p>
  <br/>
</p>
<p>
  <br/>
</p>
<p>
  <br/>
</p>
<p>
  <br/>
</p>
