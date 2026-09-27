#!/bin/sh
# Compila o DigestCalculator e os testes (JUnit 4) e executa os testes.
# Deve ser executado a partir da pasta Trabalho2.
cd "$(dirname "$0")" || exit 1
CP=".:lib/junit-4.13.2.jar:lib/hamcrest-core-1.3.jar"
javac -cp "$CP" DigestCalculator.java DigestCalculatorTest.java || exit 1
java -cp "$CP" org.junit.runner.JUnitCore DigestCalculatorTest
