.PHONY: phpunit phpstan test

phpunit:
	vendor/bin/phpunit

phpstan:
	vendor/bin/phpstan analyse --memory-limit 128M

test: phpunit phpstan
