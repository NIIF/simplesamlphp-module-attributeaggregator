<?php
/**
 * Attribute Aggregator Authentication Processing filter
 *
 * Filter for requesting the vo to give attributes to the SP.
 *
 * @author Gyula Szabó <gyufi@niif.hu>
 * @package simpleSAMLphp
 * @version $Id$
 */

class sspmod_attributeaggregator_Auth_Process_attributeaggregator extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     *
     * AA IdP entityId
     * @var string
     */
    private $entityId = null;

    /**
     *
     * attributeId, the key of the user in the AA. default is eduPersonPrincipalName
     * @var unknown_type
     */
    private $attributeId = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";

    /**
     *
     * If set to TRUE, the module will throw an exception on runtime errors
     * @var boolean
     */
    private $required = FALSE;

    /**
     * 
     * nameIdFormat, the format of the attributeId. Default is "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
     * @var unknown_type
     */
    private $nameIdFormat = SAML2\Constants::NAMEID_PERSISTENT;


    /**
     * Array of the requested attributes. Key is the attribute name, array structure is
     *   * 'values' => array()
     *   * 'multiSource' => "merge|keep|override"
     *
     * @var array
     */
    private $attributes = array();

    /**
     * nameFormat of attributes. Default is "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
     * @var string
     */
    private $attributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

    /**
     * The metadata of the AA
     *
     * @var SimpleSAML_Configuration
     */
    private $aaMetadata;

    /**
     * The URL to direct the SAML2 Attribute Query to
     *
     * @var string
     */
    private $aaEndpoint='';

    /**
     * The metadata of this SP
     *
     * @var SimpleSAML_Configuration
     */
    private $selfMetadata;

    /**
     * Initialize attributeaggregator filter
     *
     * Validates and parses the configuration
     *
     * @param array $config   Configuration information
     * @param mixed $reserved For future use
     */
    public function __construct($config, $reserved)
    {
        assert('is_array($config)');
        parent::__construct($config, $reserved);

        $metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

        // XXX We can't initialize selfMetadata now, because we can't access $state here
        // $this->selfMetadata = $metadata->getMetaDataCurrent('saml20-sp-hosted') fails
        // so we need to take the path $state->authsourceid->authsource->metadata once
        // we have $state in ::process()

        if (!empty($config["attributeId"])){
            $this->attributeId = $config["attributeId"];
        }
        
        if (!empty($config["required"])){
            $this->required = $config["required"];
        }

        if (!empty($config["nameIdFormat"])) {
            $this->nameIdFormat = $config["nameIdFormat"];
        }

        if (!empty($config["attributes"])){
            if (! is_array($config["attributes"])) {
                throw new SimpleSAML\Error\Exception("attributeaggregator: Invalid format of attributes array in the configuration");
            }
            foreach ($config["attributes"] as $attribute) {
                if (! is_array($attribute)) {
                    throw new SimpleSAML\Error\Exception("attributeaggregator: Invalid format of attributes array in the configuration");
                }
                if (array_key_exists("values", $attribute)) {
                    if (! is_array($attribute["values"])) {
                        throw new SimpleSAML\Error\Exception("attributeaggregator: Invalid format of attributes array in the configuration");
                    }    
                }
                if (array_key_exists('multiSource', $attribute)){
                    if(! preg_match('/^(merge|keep|override)$/', $attribute['multiSource']))
                        throw new SimpleSAML\Error\Exception(
                            'attributeaggregator: Invalid multiSource value "'.
                            $attribute['multiSource'].'" for '.key($attribute).
                            '. Should be one of keep, merge or override.'
                    );
                }
            }
            $this->attributes = $config["attributes"];
        }

        if (!empty($config["attributeNameFormat"])){
            $this->attributeNameFormat = $config["attributeNameFormat"];
        }

        if (isset($config['entityId'])) {
            $this->entityId = $config['entityId'];
            try {
                $this->aaMetadata = SimpleSAML_Configuration::loadFromArray(
                    $metadata->getMetaData($this->entityId, 'attributeauthority-remote')
                );
                if ($this->aaMetadata->hasValue('AttributeService')) {
                    foreach ($this->aaMetadata->getArray('AttributeService',array()) as $aa_endpoint) {
                        if ($aa_endpoint['Binding'] == SAML2\Constants::BINDING_SOAP) {
                            $this->aaEndpoint = $aa_endpoint['Location'];
                            break;
                        }
                    }
                }
                if(empty($this->aaEndpoint)) {
                    throw new RuntimeException($this->entityId.' does not have a usable AttributeService endpoint in metadata'.
                    ' with binding '.SAML2\Constants::BINDING_SOAP);
                }
            } catch (Exception $e) {
                SimpleSAML\Logger::warning('Unable to perform attribute query, no metadata for '.$this->entityId);
                if ($this->required) {
                    throw $e;
                }
            }
        }
        else {
            throw new SimpleSAML\Error\Exception(
                    'attributeaggregator: AA entityId is not specified in the configuration.'
                );
        }
    }

    /**
     * Add attributes after querying attributes from an attribute authority
     *
     * @param array &$state The state of the response.
     */
    public function process(&$state)
    {
        assert('is_array($state)');

        if (empty($this->aaMetadata) || empty($this->aaEndpoint)) {
            // We can not do anything without AA metadata but we may let others run
            // Should only reach here with $this->required===false
            SimpleSAML\Logger::debug('No AA metadata, aborting attribute query');
            return;
        }

        // We need to initialize $this->selfMetadata here, because we have just now learnt
        // the authsource we are using
        if (empty($state["saml:sp:State"]["saml:sp:AuthId"])) {
            SimpleSAML\Logger::error("Unable to access the auth source ID. Are we a SAML2 SP?");
            throw new SimpleSAML\Error\Exception("Unable to access the auth source ID");
        }
        $authsource = simpleSAML_Auth_Source::getById($state["saml:sp:State"]["saml:sp:AuthId"]);
        // This must be instanceof sspmod_saml_Auth_Source_SP
        if (!($authsource instanceof sspmod_saml_auth_Source_SP)) {
            // XXX The class name above might change in the future!
            throw new SimpleSAML\ErrorException("Auth source is not a SAML SP");
        }
        $this->selfMetadata = $authsource->getMetadata();

        try {
            // verify that we are having all the necessary information
            if (empty($state['Attributes'][$this->attributeId]) ||
                count($state['Attributes'][$this->attributeId]) > 1) {
                throw new RuntimeException("Can't attempt attribute query, attribute ".
                    $this->attributeId." is not present or has multiple values");
            }

            // build attribute query
            $query = new SAML2\AttributeQuery();
            $query->setDestination($this->aaEndpoint);
            $query->setIssuer($this->selfMetadata->getValue('entityID'));
            $nameid = SAML2\XML\saml\NameID::fromArray (
                array(
                    'Value' => $state['Attributes'][$this->attributeId][0],
                    'Format' => $this->nameIdFormat,
                )
            );
            $query->setNameId($nameid);
            $query->setAttributeNameFormat($this->attributeNameFormat);
            $query->setAttributes($this->getRequestedAttributes()); // may be empty, then it's a noop
            $query->setID(SimpleSAML\Utils\Random::generateID());
            // TODO: should this call be made optional?
            sspmod_saml_Message::addSign($this->selfMetadata,$this->aaMetadata,$query);

            // send attribute query
            SimpleSAML\Logger::debug('Sending attribute query: '.var_export($query,true));
            $binding = new SAML2\SOAPClient();
            $response = $binding->send($query,$this->selfMetadata,$this->aaMetadata);

            // verify result
            SimpleSAML\Logger::debug('Received attribute response: '.var_export($response,true));
            if (!$response->isSuccess()) {
                throw new RuntimeException('Got a SAML error on attribute query ('.
                    $response->getStatus()['Code'].')');
            }
            // merge attributes
            $assertion = $response->getAssertions()[0]; // TODO Can there be more than 1?
            if (empty($assertion)) {
                throw new RuntimeException('Got an empty SAML Response');
            }
            $this->mergeAttributes($state, $assertion->getAttributes());
        
        } catch (RuntimeException $e) {
            SimpleSAML\Logger::info("Attribute query failed: ".$e->getMessage());
            if ($this->required) {
                throw new SimpleSAML\Error\Exception($e->getMessage());
            }
        } catch (Exception $e) {
            SimpleSAML\Logger::error("Error during attribute query: ".get_class($e).
                ' '.$e->getMessage());
            throw $e;
        }
    }

    private function mergeAttributes(&$state, $attributes_from_aa) {
        if (empty($attributes_from_aa)) {
            return;
        }

        foreach ($attributes_from_aa as $name => $values) {
            // Is there a merge rule for this attribute?
            if (array_key_exists($name, $this->attributes) ||
                array_key_exists('*', $this->attributes)) {
                // Filter out values that don't match
                $this->filter_attribute_values($name,$values);
                if (empty($values)) {
                    SimpleSAML\Logger::info("[attributeaggregator] No values left for attribute ".$name);
                    continue;
                }

                // Try to obtain a merge policy. It may remain undefined
                @$mergePolicy = (isset($this->attributes[$name]) ?
                    $this->attributes[$name]['multiSource'] :
                    $this->attributes['*']['multiSource']);

                // Are we having values for the attribute before the merge?
                if (array_key_exists($name, $state['Attributes'])) {
                    // Do we have a merge policy?
                    if (isset($mergePolicy)) {
                        switch ($mergePolicy) {
                        case 'override':
                            self::override_attribute_values($state,$name,$values);
                            break;
                        case 'keep':
                            SimpleSAML\Logger::info('[attributeaggregator] Keeping attribute '.$name);
                            continue 2;
                            break;
                        case 'merge':
                            self::merge_attribute_values($state,$name,$values);
                            break;
                        }
                    }
                    // if no merge policy but the attribute is specified (or the config has a
                    // '*' default element), merge the values
                    else {
                        self::merge_attribute_values($state,$name,$values);
                    }
                } else {
                    // if the attribute hasn't existed yet, let's create it
                    self::override_attribute_values($state,$name,$values);
                }
            }
            // the attribute isn't specified in the config
            // if we have _anything_ in the attribute config, we drop what we have just received,
            // but if the attribute config part is empty, we merge it.
            else {
                if (empty($this->attributes)) {
                    self::merge_attribute_values($state,$name,$values);
                } else {
                    SimpleSAML\Logger::info("[attributeaggregator] Rejecting attribute ".$name);
                    continue;
                }
            }
        }
    }

    private function filter_attribute_values($name,&$values) {
        if (isset($this->attributes[$name]['values'])) {
            $values = array_intersect($values,$this->attributes[$name]['values']);
        } elseif (isset($this->attributes['*']['values'])) {
            $values = array_intersect($values,$this->attributes['*']['values']);
        }
        // or do nothing
    }

    private static function merge_attribute_values (&$state,$name,$values) {
        if (isset($state['Attributes'][$name])) {
            SimpleSAML\Logger::info('[attributeaggregator] Merging attribute '.$name);
            $state['Attributes'][$name] = array_merge($state['Attributes'][$name],$values);
        } else {
            self::override_attribute_values($state,$name,$values);
        }
    }

    private static function override_attribute_values (&$state,$name,$values) {
        if (!empty($state['Attributes'][$name])) {
            SimpleSAML\Logger::info('[attributeaggregator] Overriding attribute '.$name);
        } else {
            SimpleSAML\Logger::info('[attributeaggregator] Getting new attribute '.$name);
        }
        $state['Attributes'][$name] = $values;
    }

    private function getRequestedAttributes() {
        if (empty(array_keys($this->attributes))) {
            return array();
        }
        $requestedAttributes = array_flip($this->attributes);
        if(array_key_exists('*',$requestedAttributes)) {
            unset($requestedAttributes['*']);
        }
        foreach ($requestedAttributes as $attribute) {
            // we don't request specific values
            $requestedAttribute[$attribute] = array();
        }
        return $requestedAttributes;
    }

}
