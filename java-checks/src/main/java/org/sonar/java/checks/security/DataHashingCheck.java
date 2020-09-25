/*
 * SonarQube Java
 * Copyright (C) 2012-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.java.checks.security;

import java.util.Arrays;
import java.util.Optional;
import org.sonar.check.Rule;
import org.sonar.java.checks.helpers.JavaPropertiesHelper;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.java.model.ExpressionUtils;
import org.sonar.java.model.LiteralUtils;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import static org.sonar.java.checks.helpers.SecurityHelper.ALGORITHM_BY_METHOD_NAME;
import static org.sonar.java.checks.helpers.SecurityHelper.InsecureAlgorithm;
import static org.sonar.java.checks.helpers.SecurityHelper.MESSAGE_PER_CLASS;
import static org.sonar.java.checks.helpers.SecurityHelper.getWeakHashMethodInvocationMatchers;

@Rule(key = "S4790")
public class DataHashingCheck extends AbstractMethodDetection {

  @Override
  protected MethodMatchers getMethodInvocationMatchers() {
    return getWeakHashMethodInvocationMatchers();
  }

  @Override
  protected void onMethodInvocationFound(MethodInvocationTree mit) {
    IdentifierTree methodName = ExpressionUtils.methodName(mit);

    String message = MESSAGE_PER_CLASS.get(methodName.symbol().owner().type().fullyQualifiedName());
    if (message != null) {
      reportIssue(methodName, message);
      return;
    }
    InsecureAlgorithm algorithm = ALGORITHM_BY_METHOD_NAME.get(methodName.name());
    if (algorithm == null) {
      algorithm = algorithm(mit.arguments().get(0)).orElse(null);
    }
    if (algorithm != null) {
      reportIssue(methodName, "Use a stronger hashing algorithm than " + algorithm.toString() + ".");
    }
  }

  @Override
  protected void onConstructorFound(NewClassTree newClassTree) {
    String message = MESSAGE_PER_CLASS.get(newClassTree.identifier().symbolType().fullyQualifiedName());
    reportIssue(newClassTree.identifier(), message);
  }

  private static Optional<InsecureAlgorithm> algorithm(ExpressionTree invocationArgument) {
    ExpressionTree expectedAlgorithm = invocationArgument;
    ExpressionTree defaultPropertyValue = JavaPropertiesHelper.retrievedPropertyDefaultValue(invocationArgument);
    if (defaultPropertyValue != null) {
      expectedAlgorithm = defaultPropertyValue;
    }
    if (expectedAlgorithm.is(Tree.Kind.STRING_LITERAL)) {
      String algorithmName = LiteralUtils.trimQuotes(((LiteralTree) expectedAlgorithm).value());
      return Arrays.stream(InsecureAlgorithm.values())
        .filter(alg -> alg.match(algorithmName))
        .findFirst();
    }
    return Optional.empty();
  }

}
