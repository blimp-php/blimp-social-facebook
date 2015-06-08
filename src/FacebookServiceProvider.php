<?php
namespace Blimp\Accounts;

use Pimple\ServiceProviderInterface;
use Pimple\Container;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Blimp\Accounts\GrantTypes\Facebook;

class FacebookServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                $api['security.oauth.grant.urn:blimp:accounts:facebook'] = function() {
                    return new Facebook();
                };

                if($api->offsetExists('config.root')) {
                    $api->extend('config.root', function ($root, $api) {
                        $tb = new TreeBuilder();

                        $rootNode = $tb->root('facebook');

                        $rootNode
                            ->children()
                                ->scalarNode('client_id')->cannotBeEmpty()->end()
                                ->scalarNode('client_secret')->cannotBeEmpty()->end()
                                ->scalarNode('scope')->defaultValue('email')->end()
                                ->scalarNode('fields')->defaultValue('id,name,link,gender,email,picture')->end()
                                ->booleanNode('long_lived_access_token')->defaultFalse()->end()
                            ->end()
                        ;

                        $root->append($rootNode);

                        return $root;
                    });
                }
            }

            return $status;
        });
    }
}
