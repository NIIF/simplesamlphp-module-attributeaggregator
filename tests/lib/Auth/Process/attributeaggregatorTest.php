<?php

class Test_sspmod_attributeaggregator_Auth_Process_attributeaggregator extends PHPUnit_Framework_TestCase {

    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param  array $config The filter configuration.
     * @param  array $request The request state.
     * @return array  The state array after processing.
     */
    private static function processFilter(array $config, array $request)
    {
        $filter = new sspmod_attributeaggregator_Auth_Process_attributeaggregator($config, null);
        $filter->process($request);
        return $request;
    }

    public function testAny()
    {
        $this->assertTrue(true, 'Just for travis.yml test');
    }
}
