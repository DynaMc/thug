// Angler Exploit Kit (rule #1)
rule Angler_ek1 : Exploit_Kit
{
  meta:
    author = "https://github.com/DynaMc using MalwareSigs.com info"
  strings:
    $url = ^http:\/\/[^/]+\/0[a-z0-9]{13}$
  condition:
    $url
}
