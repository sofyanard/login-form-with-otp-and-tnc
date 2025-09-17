# Login Form with OTP

a simple keycloak login form with OTP and Office selection.

## How To
- compile and build
- put jar into KC deployment folder
- go to "Authentication", create new flow "Custom Form with OTP and Kantor and TnC"
- Add execution "Username Password Form", with "Required"
- Add execution "``ATR BPN OTP Kantor TnC Form", with "Required"
- add this in the ```standalone.xml```:
```
<subsystem xmlns="urn:jboss:domain:naming:2.0">
    <bindings>
        .....
        .....
        .....
        <simple name="java:/tncApiBaseUrl" value="{ATRBPN TnC API URL}" type="java.lang.String"/>
    </bindings>
    <remote-naming/>
</subsystem>
```