package org.xacml4j.opensaml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2015 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.security.credential.Credential;

/**
 * {@code SigningCredentialSelector} allows dynamically selecting {@link Credential} used for XACML
 * request signing.
 */
public interface SigningCredentialSelector {

	Credential selectCredential(RequestAbstractType request, Response response,
			IDPConfiguration idpConfiguration);
}
