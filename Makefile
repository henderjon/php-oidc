.PHONY: phpunit phpstan test

phpunit:
	vendor/bin/phpunit

phpstan:
	vendor/bin/phpstan analyse

test: phpunit phpstan
