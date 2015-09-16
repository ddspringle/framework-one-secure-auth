USE [secureauth]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[users](
	[userId] [int] IDENTITY(1,1) NOT NULL,
	[username] [varchar](max) NOT NULL,
	[password] [varchar](max) NOT NULL,
	[firstName] [varchar](max) NOT NULL,
	[lastName] [varchar](max) NOT NULL,
	[role] [int] NOT NULL,
	[isActive] [bit] NOT NULL,
 CONSTRAINT [PK_users] PRIMARY KEY CLUSTERED 
(
	[userId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO

ALTER TABLE [dbo].[users] ADD  CONSTRAINT [DF_users_role]  DEFAULT ((0)) FOR [role]
GO

ALTER TABLE [dbo].[users] ADD  CONSTRAINT [DF_users_isActive]  DEFAULT ((1)) FOR [isActive]
GO

