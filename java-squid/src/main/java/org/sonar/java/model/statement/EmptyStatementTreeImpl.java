/*
 * SonarQube Java
 * Copyright (C) 2012 SonarSource
 * dev@sonar.codehaus.org
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.java.model.statement;

import com.google.common.collect.Iterators;
import org.sonar.java.model.InternalSyntaxToken;
import org.sonar.java.model.JavaTree;
import org.sonar.plugins.java.api.tree.EmptyStatementTree;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TreeVisitor;

import java.util.Iterator;

public class EmptyStatementTreeImpl extends JavaTree implements EmptyStatementTree {
  private final InternalSyntaxToken semicolonToken;

  public EmptyStatementTreeImpl(InternalSyntaxToken semicolonToken) {
    super(Kind.EMPTY_STATEMENT);
    this.semicolonToken = semicolonToken;
    addChild(semicolonToken);
  }

  @Override
  public Kind getKind() {
    return Kind.EMPTY_STATEMENT;
  }

  @Override
  public void accept(TreeVisitor visitor) {
    visitor.visitEmptyStatement(this);
  }

  @Override
  public SyntaxToken semicolonToken() {
    return semicolonToken;
  }

  @Override
  public Iterator<Tree> childrenIterator() {
    return Iterators.emptyIterator();
  }

}
