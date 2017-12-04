Attribute Aggregator module
==============

[![Latest Stable Version](https://poser.pugx.org/niif/simplesamlphp-module-attributeaggregator/v/stable)](https://packagist.org/packages/niif/simplesamlphp-module-attributeaggregator) [![Total Downloads](https://poser.pugx.org/niif/simplesamlphp-module-attributeaggregator/downloads)](https://packagist.org/packages/niif/simplesamlphp-module-attributeaggregator)

The Attribute Aggregator module is implemented as an Authentication Processing Filter. 
It can be configured in the SP's config.php file.

It is recommended to run the Attribute Aggregator module at the SP and configure the
filter to run after the federated id, usually eduPersonPrincipalName is resolved.

  * [Read more about processing filters in simpleSAMLphp](simplesamlphp-authproc)

Install
-------------------------------

You can install the module with composer:

    composer require niif/simplesamlphp-module-attributeaggregator:1.*

How to setup the attributeaggregator module
-------------------------------

The only required option of the module is the `entityId` of the Attribute Authority to 
be queried. The AA must support `urn:oasis:names:tc:SAML:2.0:bindings:SOAP` binding.

Example:

                59 => array(
                   'class' => 'attributeaggregator:attributeaggregator',
                   'entityId' => 'https://aa.example.com:8443/aa',

                  /**
                   * The subject of the attribute query. Default: urn:oid:1.3.6.1.4.1.5923.1.1.1.6 (eduPersonPrincipalName)
                   */
                   //'attributeId' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',

                   /** 
                    * If set to TRUE, the module will throw an exception if attributeId is not found.
                    */
                   // 'required' => FALSE,

                   /** 
                    * The format of attributeId. Default is 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
                    */
                   //'nameIdFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',


                   /**
                    * The name Format of the attribute names.
                    */
                   //'attributeNameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',

                   /**
                    * The 'attributes' element specifies what to do with the attributes received from the AA.
                    * The keys of the array is the attribute name in (''urn:oid'') format.
                    * A special index '*' applies to all attributes that are not specified as an array index.
                    * If the element is undefined or empty, the filter will request all attributes and all
                    * received attributes will be merged.
                    *
                    * For each attributes the following filters can be specified:
                    *
                    *   values:
                    *     the array of acceptable values. If not defined, the filter will accept all values.
                    *   multiSource:
                    *     merge:    merge the existing and the new values, this is the default behaviour,
                    *     override: drop the existing values and set the values from AA,
                    *     keep:     drop the new values from AA and preserve the original values. Note that it
                    *               only preserves existing attributes, so if an attribute does not exist
                    *               before the filter is run, the values provided by the AA will be assigned.
                    *               Thus, if you want to limit what attributes you accept from the AA, you
                    *               can not use the default ('*') rule.
                    */
                   // 'attributes' => array(
                   //         // This rule overrides urn:oid:attribute-OID-1 if the obtained values are
                   //         // one of "value1" or "value2".
                   //         "urn:oid:attribute-OID-1" => array (
                   //               "values" => array ("value1", "value2"),
                   //               "multiSource" => "override"
                   //               ),
                   //         // This rule will add urn:oid:attribute-OID-2 only if it has not been set
                   //         // previously.
                   //         "urn:oid:attribute-OID-2" => array (
                   //               "multiSource" => "keep"
                   //               ),
                   //         // This rule merges urn:oid:attribute-OID-3 if the values are one of
                   //         // "value1" or "value2".
                   //         "urn:oid:attribute-OID-3" => array (
                   //               "values" => array ("value1", "value2"),
                   //               ),
                   //         // This rule merges all attributes that are released by the AA
                   //         "*" => array ()
                   //     ),

                ),


Options
-------

The following options can be used when configuring the '''attributeaggregation''' module

### `entityId`
The entityId of the Attribute Authority. The metadata of the AA must be in the
attributeauthority-remote metadata set, otherwise you will get an error message.

### `attributeId`
This is the *Subject* in the issued AttributeQuery. The attribute must be previously 
resolved by an authproc module. The default attribute is urn:oid:1.3.6.1.4.1.5923.1.1.1.6 
(eduPersonPrincipalName).

### `attributeNameFormat`
The format of the NameID in the issued AttributeQuery. The default value is 
`urn:oasis:names:tc:SAML:2.0:attrname-format:uri`.

### `attributes`
The `attributes` element specifies what to do with the attributes received from the AA.
The keys of the array is the attribute name in (''urn:oid'') format. A special index "*"
applies to all attributes that are not specified as an array index.
If the element is undefined or empty, the filter will request all attributes and all
received attributes will be merged.

For each attributes the following filters can be specified:

`values`
:    the array of acceptable values. If not defined, the filter will accept all values.
`multiSource`:
:    `merge`:    merge the existing and the new values, this is the default behaviour,
:    `override`: drop the existing values and set the values from AA,
:    `keep`:     drop the new values from AA and preserve the original values. Note that it
      only preserves existing attributes, so if an attribute does not exist
      before the filter is run, the values provided by the AA will be assigned.
      Thus, if you want to limit what attributes you accept from the AA, you
      can not use the default ('*') rule.
