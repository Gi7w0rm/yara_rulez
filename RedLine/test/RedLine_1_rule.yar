rule RedLine1 {
   meta:
      description = "Rule made from 719 fully unpacked samples. It detected them all. Seems to falsely detect CoinMiner.XMRig (sample: 999ad238e43d208d395a64d425f40fb1b41f0c9e70624c194e8562c6dc191caa)"
      author = "@Gi7w0rm"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-09-29"

   strings:
      $s1 = "DownloadAndExecuteUpdate" fullword ascii /* score: '22.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<ScannedFile>.GetEnumerator" fullword ascii /* score: '20.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<ScannedFile>.get_Current" fullword ascii /* score: '20.00'*/
      $s4 = "get_TaskProcessors" fullword ascii /* score: '20.00'*/
      $s5 = "get_encrypted_key" fullword ascii /* score: '17.00'*/
      $s6 = "<Processes>k__BackingField" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<ScannedFile>.Current" fullword ascii /* score: '15.00'*/
      $s8 = "ListOfProcesses" fullword ascii /* score: '15.00'*/
      $s9 = "ITaskProcessor" fullword ascii /* score: '15.00'*/
      $s10 = "<Logins>k__BackingField" fullword ascii /* score: '15.00'*/
      $s11 = "set_Processes" fullword ascii /* score: '15.00'*/
      $s12 = "<TaskProcessors>k__BackingField" fullword ascii /* score: '15.00'*/
      $s13 = "get_ScanGeckoBrowsersPaths" fullword ascii /* score: '15.00'*/
      $s14 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s15 = "BCrypt.BCryptGetProperty() failed with status code:{0}" fullword wide /* score: '15.00'*/
      $s16 = "get_ScannedFiles" fullword ascii /* score: '14.00'*/
      $s17 = "get_ScannedWallets" fullword ascii /* score: '14.00'*/
      $s18 = "ScanPasswords" fullword ascii /* score: '13.00'*/
      $s19 = "BCrypt.BCryptImportKey() failed with status code:{0}" fullword wide /* score: '13.00'*/
      $s20 = "GetWindowsVersion" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}
